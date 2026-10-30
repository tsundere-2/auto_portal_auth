    # ---- 网卡健康 ---------------------------------------------------------
    def stale_ipv4_interfaces(self, quiet_seconds: float = 120.0) -> List[Dict[str, str]]:
        """列出"有自动私有地址(169.254.x.x)且没有正常 IPv4"的网卡。

        这类网卡说明 DHCP 没拿到租约（常见于休眠后 Wi-Fi 驱动没重连上），
        它们不会进 link_info()，但会挂在系统里影响路由选择、拖慢 DNS，
        也是"僵尸网卡"的来源。返回 [{'name': ..., 'ip': ...}]，供 --fix-adapters 使用。
        """
        if psutil is None:
            return []
        ignore = [s.lower() for s in (self.cfg.get("network.ignore_interfaces") or [])]
        result: List[Dict[str, str]] = []
        now = time.time()
        try:
            stats = psutil.net_if_stats()
            addrs = psutil.net_if_addrs()
        except Exception:
            return []
        for name, st in stats.items():
            if not getattr(st, "isup", False):
                continue
            if any(pat in name.lower() for pat in ignore):
                continue
            # 刚醒来 2 分钟内的 169.254 属于正常过渡（DHCP 还在协商），不当异常报
            if now - getattr(st, "last_change", 0) < quiet_seconds:
                continue
            ipv4 = [a.address for a in addrs.get(name, [])
                    if a.family == socket.AF_INET]
            good = [a for a in ipv4
                    if not a.startswith("127.") and not a.startswith("169.254.")]
            apipa = [a for a in ipv4 if a.startswith("169.254.")]
            if apipa and not good:
                result.append({"name": name, "ip": apipa[0]})
        return result

