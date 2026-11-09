"""用标准库实现的极简 CDP 客户端（不依赖 websocket 第三方包）。

为什么需要它：
    Selenium 必须配套"版本完全匹配"的 msedgedriver，而 Edge 是自动更新的
    （实测浏览器已到 157，缓存驱动只有 155），一旦浏览器升级，
    驱动就失效 —— 表现为 "This version of Microsoft Edge WebDriver only
    supports Microsoft Edge version 155"，浏览器兜底彻底不可用。
    在需要认证的网络里又下载不了新驱动（没网），形成死循环。

    CDP（Chrome DevTools Protocol）是浏览器自带的调试协议，用 --remote-debugging-port
    启动后通过 WebSocket 通信，**完全不需要驱动**，也就永远不用跟着 Edge 升级。

只实现本任务需要的最小集合：
    Page.navigate / Page.enable / Runtime.evaluate / Target.*
"""
from __future__ import annotations

import base64
import json
import os
import socket
import struct
import time
from typing import Any, Dict, Optional


class CDPError(RuntimeError):
    pass


class _WS:
    """最小 WebSocket 客户端（RFC 6455，仅文本帧，客户端掩码）。"""

    def __init__(self, url: str, timeout: float = 10.0):
        # ws://127.0.0.1:PORT/devtools/page/XXX
        if not url.startswith("ws://"):
            raise CDPError(f"只支持 ws:// 地址: {url}")
        rest = url[5:]
        hostport, _, self.path = rest.partition("/")
        self.path = "/" + self.path
        host, _, port = hostport.partition(":")
        self.port = int(port or 80)
        self.host = host
        self.sock = socket.create_connection((self.host, self.port), timeout=timeout)
        self.sock.settimeout(timeout)
        self._handshake(hostport)
        self._buf = b""

    def _handshake(self, host_header: str) -> None:
        key = base64.b64encode(os.urandom(16)).decode()
        req = (
            f"GET {self.path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self.sock.sendall(req.encode())
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise CDPError("WebSocket 握手失败：连接被关闭")
            resp += chunk
        head = resp.split(b"\r\n\r\n", 1)[0].decode("latin-1")
        if "101" not in head.split("\r\n")[0]:
            raise CDPError(f"WebSocket 握手失败: {head.splitlines()[:2]}")
        # 握手响应之后可能已附带数据帧
        self._buf = resp.split(b"\r\n\r\n", 1)[1]

    # ---- 帧收发 -----------------------------------------------------------
    def send(self, text: str) -> None:
        payload = text.encode("utf-8")
        header = bytearray([0x81])          # FIN + text
        mask = os.urandom(4)
        n = len(payload)
        if n < 126:
            header.append(0x80 | n)
        elif n < 65536:
            header.append(0x80 | 126)
            header += struct.pack(">H", n)
        else:
            header.append(0x80 | 127)
            header += struct.pack(">Q", n)
        header += mask
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(bytes(header) + masked)

    def _read_exact(self, n: int) -> bytes:
        while len(self._buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise CDPError("WebSocket 连接已断开")
            self._buf += chunk
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def recv(self) -> str:
        while True:
            b1, b2 = self._read_exact(2)
            opcode = b1 & 0x0F
            masked = b2 & 0x80
            length = b2 & 0x7F
            if length == 126:
                length = struct.unpack(">H", self._read_exact(2))[0]
            elif length == 127:
                length = struct.unpack(">Q", self._read_exact(8))[0]
            mkey = self._read_exact(4) if masked else None
            data = self._read_exact(length)
            if mkey:
                data = bytes(b ^ mkey[i % 4] for i, b in enumerate(data))
            if opcode == 0x8:               # close
                raise CDPError("WebSocket 被对端关闭")
            if opcode == 0x9:               # ping -> pong
                self.sock.sendall(b"\x8a\x00")
                continue
            if opcode in (0x1, 0x2):
                return data.decode("utf-8", "replace")
            # 其它控制帧忽略，继续读

    def close(self) -> None:
        try:
            self.sock.sendall(b"\x88\x80" + os.urandom(4))
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass


class CDPSession:
    """连到一个 page target，提供 navigate / eval 等便捷方法。"""

    def __init__(self, ws_url: str, timeout: float = 15.0, session_id: str = ""):
        self.ws = _WS(ws_url, timeout=timeout)
        self._id = 0
        self.timeout = timeout
        # 通过 Target.attachToTarget 拿到的 sessionId：
        # 挂在 browser 级连接上，跨页面导航也不会失效。
        self.session_id = session_id

    def call(self, method: str, params: Optional[Dict[str, Any]] = None,
             timeout: Optional[float] = None) -> Dict[str, Any]:
        self._id += 1
        msg_id = self._id
        payload = {"id": msg_id, "method": method, "params": params or {}}
        if self.session_id:
            payload["sessionId"] = self.session_id
        self.ws.send(json.dumps(payload))
        deadline = time.time() + (timeout or self.timeout)
        while time.time() < deadline:
            try:
                raw = self.ws.recv()
            except (socket.timeout, TimeoutError):
                break
            try:
                data = json.loads(raw)
            except Exception:
                continue
            if data.get("id") == msg_id:
                if "error" in data:
                    raise CDPError(f"{method} 失败: {data['error']}")
                return data.get("result") or {}
            # 其它事件（Page.* / Runtime.*）丢弃，继续等自己的 id
        raise CDPError(f"{method} 超时（{timeout or self.timeout}s 内无响应）")

    def evaluate(self, expression: str, timeout: Optional[float] = None) -> Any:
        # 必须先 Runtime.enable，否则部分 Edge 版本不回 evaluate 的消息
        if not getattr(self, "_runtime_ready", False):
            try:
                self.call("Runtime.enable", {}, timeout=timeout)
            except CDPError:
                pass
            self._runtime_ready = True
        res = self.call("Runtime.evaluate", {
            "expression": expression,
            "returnByValue": True,
            "awaitPromise": True,
        }, timeout=timeout)
        if res.get("exceptionDetails"):
            raise CDPError(f"JS 异常: {res['exceptionDetails'].get('text')}")
        return (res.get("result") or {}).get("value")

    def navigate(self, url: str, timeout: Optional[float] = None) -> None:
        self.call("Page.navigate", {"url": url}, timeout=timeout)

    def close(self) -> None:
        self.ws.close()


def list_targets(port: int, timeout: float = 5.0) -> list:
    """列出浏览器里的所有 target（用 HTTP /json，不占 WebSocket）。"""
    import http.client
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        conn.request("GET", "/json/list")
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return json.loads(data.decode("utf-8", "replace"))
    except Exception:
        return []


def wait_port(port: int, timeout: float = 15.0) -> bool:
    """等调试端口就绪。"""
    import http.client
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=1.5)
            conn.request("GET", "/json/version")
            if conn.getresponse().status == 200:
                conn.close()
                return True
            conn.close()
        except Exception:
            time.sleep(0.25)
    return False


class Browser:
    """浏览器级 CDP 连接。

    与直连 page target 的区别：页面导航会重建渲染进程，直连的 WebSocket
    会失效（实测 navigate 之后所有 evaluate 超时）。走 Target.attachToTarget
    拿到 sessionId 后，即使页面跳转，session 仍然有效。
    """

    def __init__(self, port: int, timeout: float = 15.0):
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/json/version")
        ver = json.loads(conn.getresponse().read().decode("utf-8", "replace"))
        conn.close()
        self.port = port
        self.ws_url = ver["webSocketDebuggerUrl"]
        self.version = ver
        self._base = CDPSession(self.ws_url, timeout=timeout)
        self._sid = 1

    @property
    def browser_version(self) -> str:
        return str(self.version.get("Browser") or "")

    def new_page(self) -> "Page":
        """新建一个标签页并附加。"""
        res = self._base.call("Target.createTarget", {"url": "about:blank"})
        target_id = res["targetId"]
        att = self._base.call("Target.attachToTarget",
                              {"targetId": target_id, "flatten": True})
        return Page(self._base, target_id, att["sessionId"])

    def first_page(self) -> Optional["Page"]:
        """拿一个"普通网页"标签页。

        坑：Edge 启动后常有 `edge://sync-confirmation-dialog/`、
        `edge://newtab/` 之类的内置页面排在前面，直接取 pages[0] 会连错，
        导致后续所有 evaluate 都卡住（实测白等 45 秒）。
        这里按"优先 about:blank / http(s)"挑选。
        """
        infos = (self._base.call("Target.getTargets") or {}).get("targetInfos") or []
        pages = [t for t in infos if t.get("type") == "page"]

        def rank(t):
            u = str(t.get("url") or "")
            if u == "about:blank":
                return 0
            if u.startswith("http://") or u.startswith("https://"):
                return 1
            return 2                     # edge:// 等内置页，最后才用

        pages.sort(key=rank)
        if not pages:
            return self.new_page()
        target_id = pages[0]["targetId"]
        att = self._base.call("Target.attachToTarget",
                              {"targetId": target_id, "flatten": True})
        return Page(self._base, target_id, att["sessionId"])

    def close(self) -> None:
        try:
            self._base.close()
        except Exception:
            pass


class Page:
    """一个已附加的标签页。"""

    def __init__(self, base: CDPSession, target_id: str, session_id: str):
        self.base = base
        self.target_id = target_id
        self.sid = session_id
        self._enabled = False

    def _call(self, method: str, params: Optional[Dict[str, Any]] = None,
              timeout: Optional[float] = None) -> Dict[str, Any]:
        saved = self.base.session_id
        self.base.session_id = self.sid
        try:
            return self.base.call(method, params, timeout=timeout)
        finally:
            self.base.session_id = saved

    def enable(self) -> None:
        if self._enabled:
            return
        try:
            self._call("Page.enable")
        except CDPError:
            pass
        try:
            self._call("Runtime.enable")
        except CDPError:
            pass
        self._enabled = True

    def navigate(self, url: str, timeout: Optional[float] = None,
                 wait_load: bool = False) -> None:
        """导航到指定 URL。

        wait_load=False（默认）只等"导航指令被接受"，不等页面 load：
        Portal 认证页常引用外网资源，认证前那些请求会一直挂起，
        等 load 会白等几十秒（实测 45 秒），完全没必要 ——
        我们只需要 DOM 就绪就能填表和点击。
        """
        self._call("Page.navigate", {"url": url},
                   timeout=timeout if wait_load else min(timeout or 8.0, 8.0))

    def evaluate(self, expression: str, timeout: Optional[float] = None) -> Any:
        self.enable()
        res = self._call("Runtime.evaluate", {
            "expression": expression,
            "returnByValue": True,
            "awaitPromise": True,
        }, timeout=timeout)
        if res.get("exceptionDetails"):
            raise CDPError(f"JS 异常: {res['exceptionDetails'].get('text')}")
        return (res.get("result") or {}).get("value")

    def close(self) -> None:
        try:
            self._call("Page.close")
        except CDPError:
            pass
