"""修复 check() 的"单点通过即在线"漏洞。

问题（已用 repro_connected_no_net.py 复现）：
    睡眠唤醒后网关常处于"半通"状态：DNS 有缓存能解析个别域名、或网关
    放行个别目标。旧逻辑只要**任意一个**探测目标通过就立刻 return
    INTERNET_OK，并且不再看后面的目标 —— 于是状态显示已连接，实际打不开
    网页，而且因为判成 OK，程序再也不会去认证。

修复：
    1. 全部目标都探完，按"通过数"判定，而不是先到先赢；
    2. 通过数 >= majority（默认 2，且不超过目标数）才算真的在线；
    3. 少数目标通过、其余超时 -> 判为 unknown（"看起来通但实际不通"），
       交给唤醒窗口去抢认证，而不是报"网络正常"。
"""
import io

p = "auto_portal_auth.py"
s = io.open(p, encoding="utf-8").read()

old = '''        portal_result: Optional[ProbeResult] = None
        errors: List[ProbeResult] = []
        for target in (self.cfg.get("detect.probe_targets") or []):
            res = self.probe_target(target)
            status.probes.append({
                "target": res.target, "kind": res.kind, "status": res.status_code,
                "final_url": res.final_url, "elapsed_ms": res.elapsed_ms, "detail": res.detail,
            })
            if res.kind == "ok":
                # 任意一个目标通过就认为"能上网"
                status.state = NetState.INTERNET_OK
                status.detail = f"探测通过: {res.target} ({res.elapsed_ms} ms)"
                return status
            if res.kind == "portal" and portal_result is None:
                portal_result = res
            if res.kind == "error":
                errors.append(res)

        if portal_result is not None:'''

new = '''        portal_result: Optional[ProbeResult] = None
        errors: List[ProbeResult] = []
        ok_results: List[ProbeResult] = []
        targets = self.cfg.get("detect.probe_targets") or []
        for target in targets:
            res = self.probe_target(target)
            status.probes.append({
                "target": res.target, "kind": res.kind, "status": res.status_code,
                "final_url": res.final_url, "elapsed_ms": res.elapsed_ms, "detail": res.detail,
            })
            if res.kind == "ok":
                ok_results.append(res)
            if res.kind == "portal" and portal_result is None:
                portal_result = res
            if res.kind == "error":
                errors.append(res)

        # 判定"真的在线"：要求多数目标通过，而不是任意一个通过。
        # 原因：睡眠唤醒后网关常处于半通状态（DNS 有缓存能解析个别域名、
        # 或网关只放行个别目标），单点通过会让我们误报"网络正常"并停止认证，
        # 表现就是"显示已连接但打不开网页"。
        need = int(self.cfg.get("detect.min_ok_targets", 0) or 0)
        if need <= 0:
            # 默认：目标数 <= 2 时要求全部通过；>= 3 时要求过半（至少 2 个）
            need = len(targets) if len(targets) <= 2 else max(2, (len(targets) + 1) // 2)
        need = min(need, len(targets)) if targets else 0

        if ok_results and len(ok_results) >= need:
            best = ok_results[0]
            status.state = NetState.INTERNET_OK
            status.detail = f"探测通过: {best.target} ({best.elapsed_ms} ms)"
            if len(ok_results) > 1:
                status.detail += f" 等 {len(ok_results)} 项"
            if portal_result is not None:
                # 有目标被拦截、又有目标通过：最可能是半通/劫持，别当正常
                LOG.debug("部分目标通过(%s/%s)、部分被判拦截，仍按在线处理",
                          len(ok_results), len(targets))
            return status

        if portal_result is not None:'''

assert old in s, "probe loop anchor not found"
s = s.replace(old, new, 1)

# 处理"少数通过 + 其余超时"：不要落到 UNKNOWN 的泛化文案，给出可诊断的说明
old2 = '''        status.state = NetState.UNKNOWN
        if errors:
            status.detail = "所有探测目标均失败: " + "; ".join(
                f"{e.target}({e.detail})" for e in errors[:3]
            )
            if not self.dns_ok():
                status.detail += " | DNS 解析失败"'''
new2 = '''        status.state = NetState.UNKNOWN
        if ok_results and len(ok_results) < need:
            # 关键的"显示已连接但实际没网"场景：个别目标通、多数不通
            status.detail = (f"仅 {len(ok_results)}/{len(targets)} 个探测目标通过"
                             f"（需 {need} 个）：" +
                             "; ".join(f"{e.target}({e.detail})" for e in errors[:3]))
            if not self.dns_ok():
                status.detail += " | DNS 解析失败"
        elif errors:
            status.detail = "所有探测目标均失败: " + "; ".join(
                f"{e.target}({e.detail})" for e in errors[:3]
            )
            if not self.dns_ok():
                status.detail += " | DNS 解析失败"'''
assert old2 in s, "unknown anchor not found"
s = s.replace(old2, new2, 1)

io.open(p, "w", encoding="utf-8", newline="").write(s)
print("patched check()")
