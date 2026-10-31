"""修复"unknown 状态超过唤醒容忍窗口后不再自愈"的漏洞。

问题：
    _handle_unknown 只在唤醒后 wake_unknown_tolerance（默认 30s）内抢认证；
    超过这个窗口，只打一条"网络探测异常"日志 + 结束会话，之后就是每 15 秒
    探一次、永远 unknown，永远不会去认证 —— 这正是"长时间睡眠后显示已连接
    但实际没网、而且一直不恢复"的直接原因。

修复：
    1. 超过容忍窗口后，再做一次"定向判定"：直接请求 Portal 网关（IP 直连，
       不依赖 DNS）。能拿到认证页 -> 说明只是没认证，立刻转 portal_required；
    2. 若连网关都不可达，才认为上游/链路问题，保持 unknown 但继续低频重试；
    3. 全程有节流，不会刷爆网关。
"""
import io

p = "auto_portal_auth.py"
s = io.open(p, encoding="utf-8").read()

old = '''        if prev.state is NetState.INTERNET_OK:
            LOG.warning("网络探测异常（可能上游故障）: %s", status.detail)
            self._end_session("unknown", status)
        else:
            LOG.info("状态未知: %s", status.detail)'''

new = '''        if prev.state is NetState.INTERNET_OK:
            LOG.warning("网络探测异常（可能上游故障）: %s", status.detail)
            self._end_session("unknown", status)
        else:
            LOG.info("状态未知: %s", status.detail)

        # 关键自愈：超过唤醒容忍窗口仍然 unknown，不能就此"躺平"。
        # 探测要 DNS，但 Portal 网关是 IP 直连 —— 直接问它就知道是
        # "没认证"还是"真断网"。这是长时间睡眠后能自动恢复的关键一步。
        if self._portal_selfcheck(status):
            return

    def _portal_selfcheck(self, status: NetStatus) -> bool:
        """unknown 时的定向判定：直接问 Portal 网关，是"没认证"就立刻去认证。

        只在探测持续失败时调用（有节流），避免无谓开销。
        返回 True 表示已经转到 portal_required 并交给认证流程。
        """
        if not self.cfg.get("monitor.portal_selfcheck", True):
            return False
        interval = max(5.0, float(self.cfg.get("monitor.portal_selfcheck_interval", 20.0)))
        now = time.monotonic()
        if self._last_selfcheck and now - self._last_selfcheck < interval:
            return False
        self._last_selfcheck = now

        link = self.checker.link_info()
        if not link.up or not link.has_ip:
            return False

        # 优先用上次缓存的认证页（IP 直连，不需要 DNS）
        cache = self._portal_cache or {}
        candidate = str(cache.get("url") or "")
        if candidate:
            html = self.checker._fetch_portal_page(candidate)
            if html:
                LOG.info("主动探测认证页成功（%s），判定为需要认证", candidate.split("?")[0])
                portal = NetStatus(
                    state=NetState.PORTAL_REQUIRED, portal_url=candidate,
                    local_ip=link.primary_ip, interface=link.primary_iface)
                portal.fingerprint = guess_vendor(candidate, html)
                portal.fingerprint.portal_url = candidate
                self.status = portal
                self._handle_portal(portal, status, False)
                return True
            LOG.debug("缓存的认证页已不可达: %s", candidate.split("?")[0])
        else:
            # 没有缓存：试着用一个常见网关地址探一下，成功就记下来
            for guess in (self.cfg.get("monitor.portal_guess_urls") or []):
                html = self.checker._fetch_portal_page(str(guess))
                if html:
                    LOG.info("探测到 Portal 网关: %s", str(guess).split("?")[0])
                    self._save_portal_cache(
                        NetStatus(state=NetState.PORTAL_REQUIRED, portal_url=str(guess),
                                  local_ip=link.primary_ip), str(guess))
                    portal = NetStatus(
                        state=NetState.PORTAL_REQUIRED, portal_url=str(guess),
                        local_ip=link.primary_ip, interface=link.primary_iface)
                    portal.fingerprint = guess_vendor(str(guess), html)
                    portal.fingerprint.portal_url = str(guess)
                    self.status = portal
                    self._handle_portal(portal, status, False)
                    return True
        return False'''

assert old in s, "unknown tail anchor not found"
s = s.replace(old, new, 1)

# 初始化节流字段
old2 = '''        self._skip_tick = False            # 本轮跳过完整探测（抢跑窗口内 DNS 未就绪）'''
new2 = '''        self._skip_tick = False            # 本轮跳过完整探测（抢跑窗口内 DNS 未就绪）
        self._last_selfcheck = 0.0         # 上次"直接问 Portal 网关"的时刻（节流用）'''
assert old2 in s, "init anchor not found"
s = s.replace(old2, new2, 1)

io.open(p, "w", encoding="utf-8", newline="").write(s)
print("patched _handle_unknown + selfcheck")
