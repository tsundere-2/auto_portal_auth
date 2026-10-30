# ===========================================================================
# 3. 崩溃 / 异常退出诊断
# ===========================================================================
# 背景：2026-10-29 21:01 守护进程静默消失，日志戛然而止、没有 WER 记录，
# 只能靠倒推系统事件才判断出"进程没了"。这个模块的目的就是让下次
# 死掉时能直接看到死因，而不是再猜一遍。

def install_crash_diagnostics(cfg: Config, crash_log: Optional[Path] = None) -> None:
    """安装三层退出诊断，全部写入 logs/crash.log。

    1. faulthandler：段错误 / abort / 栈溢出这类"Python 层抓不到"的硬崩溃，
       会打印完整 Python 调用栈（这是唯一能抓到 native 崩溃的手段）。
    2. excepthook：主线程未捕获异常。
    3. threading.excepthook：后台线程（电源监听、Selenium）抛的异常。
    另外挂一个 atexit 钩子，正常退出也会记一笔，便于区分"正常停"和"被杀"。
    """
    path = crash_log or cfg.resolve_path(
        cfg.get("app.crash_log_file", "logs/crash.log"))
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        f = path.open("a", encoding="utf-8")
    except Exception as exc:      # 日志目录不可写时不影响主功能
        print(f"[!] 初始化崩溃日志失败: {exc}", file=sys.stderr)
        return

    # 1) 硬崩溃：保留全部线程栈
    try:
        faulthandler.enable(file=f, all_threads=True)
    except Exception:
        pass

    def _stamp() -> str:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _excepthook(exc_type, exc, tb):
        import traceback
        f.write(f"\n===== {_stamp()} 未捕获异常 pid={os.getpid()} =====\n")
        traceback.print_exception(exc_type, exc, tb, file=f)
        f.flush()
        LOG.error("未捕获异常，详情见 %s", path)

    def _thread_hook(args):
        import traceback
        if args.exc_type is SystemExit:
            return
        f.write(f"\n===== {_stamp()} 线程异常 {getattr(args.thread, 'name', '?')} "
                f"pid={os.getpid()} =====\n")
        traceback.print_exception(args.exc_type, args.exc_value,
                                  args.exc_traceback, file=f)
        f.flush()

    sys.excepthook = _excepthook
    try:
        threading.excepthook = _thread_hook
    except Exception:
        pass

    # 4) 正常退出也留一笔：没有这一笔又没崩溃记录 => 被外部强杀
    def _on_exit():
        try:
            f.write(f"\n===== {_stamp()} 进程正常退出 pid={os.getpid()} =====\n")
            f.flush()
        except Exception:
            pass

    atexit.register(_on_exit)
    LOG.debug("崩溃诊断已启用: %s", path)


