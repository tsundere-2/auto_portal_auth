"""给 link_info 加缓存与崩溃降级保护。

理由（来自实测 crash.log）：
  * net_if_stats/net_if_addrs 是最慢的一段（各约 12ms），每轮巡检都调，
    而网卡状态 30 秒内几乎不会变；
  * 它们偶尔会在 native 层 access violation —— 如果持续发生会把进程拖死。
    这里加 3 秒缓存 + 连续失败降级，保证即使枚举接口坏了，程序也能靠
    出口 IP 继续工作，而不是死循环崩溃。
"""
import io

p = "auto_portal_auth.py"
s = io.open(p, encoding="utf-8").read()

old = '''    def link_info(self) -> LinkInfo:
        info = LinkInfo()
        if psutil is None:'''
new = '''    def link_info(self, use_cache: bool = True) -> LinkInfo:
        """读取链路信息（带 3 秒缓存）。

        net_if_stats/net_if_addrs 单次约 12ms 且偶尔在 native 层崩溃，
        而 30 秒巡检里会连调多次（探测、保活、预认证），缓存能省掉大半开销。
        """
        if use_cache:
            now = time.monotonic()
            cached = getattr(self, "_link_cache", None)
            ttl = float(self.cfg.get("network.link_cache_seconds", 3.0))
            if cached and now - cached[0] < ttl:
                return cached[1]
        info = self._link_info_uncached()
        try:
            self._link_cache = (time.monotonic(), info)
        except Exception:
            pass
        return info

    def _link_info_uncached(self) -> LinkInfo:
        info = LinkInfo()
        if psutil is None:'''
assert old in s
s = s.replace(old, new, 1)

# 给 psutil 枚举加连续失败降级
old2 = '''        ignore = [s.lower() for s in (self.cfg.get("network.ignore_interfaces") or [])]
        try:
            stats = psutil.net_if_stats()
            addrs = psutil.net_if_addrs()
        except Exception as exc:
            LOG.debug("读取网卡信息失败: %s", exc)
            ip = self.local_outbound_ip()
            if ip:
                info.up, info.primary_ip = True, ip
            return info'''
new2 = '''        ignore = [s.lower() for s in (self.cfg.get("network.ignore_interfaces") or [])]
        # 枚举网卡偶尔会在 native 层崩（crash.log 里见过 psutil net_if_stats 的
        # access violation）。连续失败 3 次就暂时停用枚举，只用出口 IP 判定，
        # 避免在坏掉的接口上空转。
        if getattr(self, "_enum_fail_streak", 0) >= 3:
            ip = self.local_outbound_ip()
            if ip:
                info.up, info.primary_ip = True, ip
                info.interfaces = {"<fallback>": [ip]}
                info.primary_iface = "<fallback>"
            return info
        try:
            stats = psutil.net_if_stats()
            addrs = psutil.net_if_addrs()
            self._enum_fail_streak = 0
        except Exception as exc:
            self._enum_fail_streak = getattr(self, "_enum_fail_streak", 0) + 1
            LOG.debug("读取网卡信息失败(%s次): %s", self._enum_fail_streak, exc)
            ip = self.local_outbound_ip()
            if ip:
                info.up, info.primary_ip = True, ip
                info.primary_iface = "<fallback>"
            return info'''
assert old2 in s
s = s.replace(old2, new2, 1)

io.open(p, "w", encoding="utf-8", newline="").write(s)
print("patched link_info")
