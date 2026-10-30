def cmd_fix_adapters(cfg: Config, args) -> int:
    """清理"拿到 169.254 自动私有地址"的僵尸网卡。

    休眠唤醒后 Wi-Fi 驱动经常只完成重新关联、不做 DHCP，网卡就卡在
    169.254.x.x。这类网卡不参与认定（link_info 会跳过），但仍挂在系统里
    影响路由和 DNS 解析。修复顺序由轻到重：
      1. ipconfig /renew（只续租，无感）
      2. netsh 禁用 / 启用该网卡（会短暂断一下该网卡）
    默认 --dry-run 只报告不动手，避免误伤正在用的链路。
    """
    checker = NetworkChecker(cfg)
    stale = checker.stale_ipv4_interfaces()
    print(f"检测到 {len(stale)} 个异常网卡（169.254 自动私有地址，DHCP 未成功）：")
    for item in stale:
        print(f"  - {item['name']}  {item['ip']}")
    if not stale:
        print("无需处理。")
        return 0

    names = [item["name"] for item in stale]
    if args.only:
        names = [n for n in names if any(k.lower() in n.lower() for k in args.only)]
        if not names:
            print("按 --only 过滤后没有需要处理的网卡。")
            return 0

    if getattr(args, "dry_run", False):
        print("\n[dry-run] 未做任何改动。加 --apply 才会真正执行。")
        return 0

    ok, fail = [], []
    for name in names:
        print(f"\n>>> 处理: {name}")
        # 1) 续租：先试最轻的手段
        r = subprocess.run(["ipconfig", "/renew", name], capture_output=True,
                           text=True, encoding="mbcs", errors="replace",
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        print(f"    ipconfig /renew -> rc={r.returncode}")
        time.sleep(2)
        left = [x["name"] for x in checker.stale_ipv4_interfaces()]
        if name not in left:
            print(f"    [OK] {name} 已拿到正常地址")
            ok.append(name)
            continue
        # 2) 重启网卡
        for action in ("disable", "enable"):
            subprocess.run(["netsh", "interface", "set", "interface",
                            f"name={name}", f"admin={action}"],
                           capture_output=True,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            time.sleep(3 if action == "disable" else 6)
        left = [x["name"] for x in checker.stale_ipv4_interfaces()]
        if name not in left:
            print(f"    [OK] {name} 重启网卡后已恢复")
            ok.append(name)
        else:
            print(f"    [FAIL] {name} 仍是 169.254，可能需要重装/更新驱动")
            fail.append(name)

    print(f"\n完成：成功 {len(ok)}，失败 {len(fail)}")
    if fail:
        print("失败项建议手动处理（设备管理器里禁用再启用，或更新驱动）：", ", ".join(fail))
        return 2
    return 0


