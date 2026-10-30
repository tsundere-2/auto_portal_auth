def _watchdog_task_name() -> str:
    return "AutoPortalAuthWatchdog"


def _watchdog_xml(command: str, workdir: str, interval_minutes: int) -> str:
    """生成计划任务 XML。

    关键三点（对应实战中"睡醒后没人拉起进程"的问题）：
      * 多个触发器：登录时 + 每 N 分钟 + **唤醒时（BootTrigger 不行，用 EventTrigger
        监听 Kernel-Power 107 恢复事件）**，保证一醒来就有人检查；
      * 任务设置为"唤醒后立即运行"、"错过则尽快补跑"；
      * 用 pythonw 静默运行，不弹黑框。
    """
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>AutoPortalAuth 看门狗：守护进程不在就拉起；唤醒后立即检查一次。</Description>
    <URI>\\{_watchdog_task_name()}</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <Delay>PT20S</Delay>
    </LogonTrigger>
    <TimeTrigger>
      <Repetition>
        <Interval>PT{interval_minutes}M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>2026-01-01T00:00:00</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="System"&gt;&lt;Select Path="System"&gt;*[System[Provider[@Name='Microsoft-Windows-Kernel-Power'] and (EventID=107 or EventID=131)]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
      <Delay>PT3S</Delay>
    </EventTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{_current_user()}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT5M</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{_xml_escape(command)}</Command>
      <Arguments>{_xml_escape("-X utf8")}</Arguments>
      <WorkingDirectory>{_xml_escape(workdir)}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"""


def _current_user() -> str:
    try:
        user = os.environ.get("USERNAME") or ""
        domain = os.environ.get("USERDOMAIN") or ""
        return f"{domain}\\{user}" if domain else user
    except Exception:
        return ""


def _xml_escape(text: str) -> str:
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def find_running_daemon(cfg: Config) -> Optional[int]:
    """找到正在运行的守护进程 PID（读锁文件，并校验进程真的活着）。"""
    lock_path = cfg.resolve_path(cfg.get("app.lock_file", "data/auto_portal_auth.lock"))
    try:
        if not lock_path.exists():
            return None
        pid = int((lock_path.read_text(encoding="utf-8") or "0").strip() or 0)
    except Exception:
        return None
    return pid if SingleInstance._pid_alive(pid) else None


def cmd_watchdog(cfg: Config, args) -> int:
    """看门狗本体：守护进程不在就拉起。

    设计要点：
      * 只用"锁文件 + 进程存活"判断，不碰网络，秒级完成；
      * 拉起后短暂等待确认，失败则重试（默认 3 次）；
      * 被计划任务每 N 分钟 + 系统唤醒时触发，自身不常驻，零资源占用。
    """
    pid = find_running_daemon(cfg)
    if pid:
        print(f"守护进程在运行 (pid={pid})，无需处理。")
        return 0
    if getattr(args, "check", False):
        print("守护进程未运行。")
        return 1

    args_list, pretty = autostart_command(cfg, args.config)
    tries = max(1, int(getattr(args, "retries", 3) or 1))
    for attempt in range(1, tries + 1):
        print(f"[{attempt}/{tries}] 拉起守护进程: {pretty}")
        try:
            kwargs = {"close_fds": True}
            if platform.system() == "Windows":
                kwargs["creationflags"] = getattr(subprocess, "DETACHED_PROCESS", 0) | \
                    getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            subprocess.Popen(args_list, cwd=str(Path(__file__).resolve().parent),
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             stdin=subprocess.DEVNULL, **kwargs)
        except Exception as exc:
            print(f"    启动失败: {exc}")
        for _ in range(20):            # 最多等 6 秒
            time.sleep(0.3)
            pid = find_running_daemon(cfg)
            if pid:
                print(f"    [OK] 已拉起 (pid={pid})")
                return 0
        time.sleep(1)
    print("    [FAIL] 多次尝试仍未拉起，请手动运行 `python auto_portal_auth.py run` 查看报错。")
    return 1


def cmd_watchdog_install(cfg: Config, args) -> int:
    """把看门狗注册成 Windows 计划任务（登录 / 每 N 分钟 / 系统唤醒 三种触发）。"""
    if platform.system() != "Windows":
        print("该命令目前只支持 Windows。")
        return 2
    interval = max(1, int(getattr(args, "interval", 5) or 5))
    python = Path(sys.executable)
    # 用 pythonw 启动，避免计划任务里闪黑框
    pyw = python.with_name("pythonw.exe")
    exe = pyw if pyw.exists() else python
    script = Path(__file__).resolve()
    workdir = str(script.parent)
    command = f'"{exe}" "{script}"'
    xml = _watchdog_xml(command, workdir, interval)

    tmp = Path(tempfile.gettempdir()) / "apa_watchdog.xml"
    # schtasks 要求 UTF-16
    tmp.write_text(xml, encoding="utf-16")
    name = _watchdog_task_name()
    try:
        if getattr(args, "remove", False):
            subprocess.run(["schtasks", "/Delete", "/TN", name, "/F"],
                           capture_output=True)
            print(f"已删除计划任务 {name}")
            return 0
        r = subprocess.run(["schtasks", "/Create", "/TN", name, "/XML", str(tmp), "/F"],
                           capture_output=True, text=True, encoding="mbcs", errors="replace")
        if r.returncode != 0:
            err = (r.stdout or "") + (r.stderr or "")
            print("创建计划任务失败：", err.strip())
            if "拒绝访问" in err or "Access is denied" in err:
                print("提示：需要以管理员身份运行一次本命令。")
            return 1
        print(f"已创建计划任务 {name}")
        print(f"  触发：登录后 20 秒 / 每 {interval} 分钟 / 系统唤醒后 3 秒")
        print(f"  命令：{command} watchdog")
    finally:
        try:
            tmp.unlink()
        except Exception:
            pass

    if not getattr(args, "no_start", False):
        print("\n立即执行一次看门狗检查：")
        return cmd_watchdog(cfg, args)
    return 0


