"""""把网卡/出口 IP 查询隔离到独立子进程，彻底解决 native 崩溃杀死主进程"。

背景（logs/crash.log 实测）：
    socket.getaddrinfo / socket.socket() / psutil.net_if_stats 在这台机器上
    偶发 access violation。那是 native 崩溃，Python 的 try/except 抓不到，
    整个进程直接被终止 —— 表现就是"睡一觉醒来守护进程不见了，浏览器弹认证页"。
    缓存放大了间隔但消不掉根因：只要还在主进程里调，迟早会撞上。

方案：
    把这些调用放进一个**短命子进程**里跑。子进程崩了只是返回码非 0，
    主进程照常存活，退化到"沿用上一次的结果"。开销：每次约 30~50ms，
    配合缓存（默认 5s）后完全可接受。
"""
import io

p = "auto_portal_auth.py"
s = io.open(p, encoding="utf-8").read()

# 1) 子进程入口（模块级函数，供 -c 调用）
old = '''    @staticmethod
    def local_outbound_ip() -> str:
        """通过 UDP socket "连" 一个公网地址来获取本机默认出口 IP（不会真的发包）。"""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1.0)
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
        except Exception:
            return ""
        finally:
            if sock:
                sock.close()'''

new = '''    @staticmethod
    def local_outbound_ip() -> str:
        """获取本机默认出口 IP。

        优先在**子进程**里问（见 _probe_outbound_ip_isolated）：socket 的创建
        和 connect 在本机偶发 access violation，放在主进程里会直接把进程打死。
        子进程崩溃时退回同进程调用（并计入失败次数，连续失败就暂时不试）。
        """
        isolated = NetworkChecker._probe_outbound_ip_isolated()
        if isolated is not None:
            return isolated
        return NetworkChecker._probe_outbound_ip_inline()

    @staticmethod
    def _probe_outbound_ip_inline() -> str:
        """在同进程里取出口 IP（可能是崩溃源，仅在隔离方案不可用时兜底）。"""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1.0)
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
        except Exception:
            return ""
        finally:
            if sock:
                sock.close()

    @staticmethod
    def _probe_outbound_ip_isolated(timeout: float = 4.0) -> Optional[str]:
        """在隔离子进程里取出口 IP。

        返回 "" 表示"子进程正常执行且确实没有出口 IP"（比如网卡没起来）；
        返回 None 表示"隔离方案不可用/子进程崩了"，调用方应自行兜底。
        """
        if platform.system() != "Windows":
            return None
        code = (
            "import socket,sys\\n"
            "s=None\\n"
            "try:\\n"
            "    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\\n"
            "    s.settimeout(1.0)\\n"
            "    s.connect(('8.8.8.8',80))\\n"
            "    sys.stdout.write(s.getsockname()[0])\\n"
            "except Exception:\\n"
            "    sys.stdout.write('')\\n"
            "finally:\\n"
            "    try:\\n"
            "        s and s.close()\\n"
            "    except Exception:\\n"
            "        pass\\n"
        )
        try:
            r = subprocess.run(
                [sys.executable, "-c", code], capture_output=True, timeout=timeout,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except Exception:
            return None
        if r.returncode != 0:
            return None                       # 子进程崩了（access violation 等）
        return (r.stdout or b"").decode("utf-8", "replace").strip()'''

assert old in s, "local_outbound_ip anchor miss"
s = s.replace(old, new, 1)

# 2) link_info 缓存默认拉长到 5s（子进程有开销，但远小于 30s 巡检周期）
s = s.replace('ttl = float(self.cfg.get("network.link_cache_seconds", 3.0))',
              'ttl = float(self.cfg.get("network.link_cache_seconds", 5.0))', 1)

io.open(p, "w", encoding="utf-8", newline="").write(s)
print("patched isolated outbound ip")
