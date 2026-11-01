"""新增独立唤醒抢连线程。

为什么还需要它：
    主循环的 _sleep 是"分片等待 + poll"，只有轮询到 resume 事件才会动作。
    而 11-01 那次 11.8 小时睡眠证明了一个更糟的情况：进程在睡眠期间就没了，
    主循环根本不存在，任何在"主循环里"做的优化都无从执行。

    所以这里补两件事：
      1. WakeFastThread：一个极轻的独立线程，每 1 秒 poll 一次唤醒事件。
         一旦检测到 resume，立刻（不排队、不等主循环）抢一次直连登录，
         再顺手把主循环的抢跑窗口打开。
      2. 让 _sleep 的唤醒分支把"已经抢过"的事实复用，避免重复登录。
"""
import io

p = "auto_portal_auth.py"
s = io.open(p, encoding="utf-8").read()

# 1) 独立唤醒线程类，插到 AutoPortalAuth 之前
anchor = "class AutoPortalAuth:"
assert anchor in s
new_cls = '''class WakeFastThread(threading.Thread):
    """独立线程：以 1 秒节奏盯着唤醒事件，醒来立刻抢连。

    与主循环解耦的好处：
      * 主循环可能正卡在一次 30 秒的巡检等待里，或在一个慢探测里；
      * 这个线程只做 poll + 一次直连登录，不跑完整探测，开销极小；
      * 即使它自己出异常，也只是这个线程退出，不影响主循环。
    """

    def __init__(self, owner: "AutoPortalAuth"):
        super().__init__(name="wake-fast", daemon=True)
        self.owner = owner
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:                      # pragma: no cover - 线程
        LOG.debug("唤醒抢连线程已启动（1s 轮询）")
        last_handled = 0.0
        while not self._stop.wait(1.0):
            try:
                events = self.owner.watcher.poll()
            except Exception as exc:
                LOG.debug("唤醒线程 poll 异常: %s", exc)
                continue
            if "resume" not in events:
                continue
            now = time.monotonic()
            if now - last_handled < 15:
                continue                         # 同一次唤醒去重
            last_handled = now
            try:
                self.owner.on_wake_fast()
            except Exception as exc:
                LOG.warning("唤醒抢连异常: %s", exc)


'''
s = s.replace(anchor, new_cls + anchor, 1)

# 2) on_wake_fast：唤醒瞬间的立即动作
anchor2 = "    def _wake_window_active(self) -> bool:"
assert anchor2 in s
new_fn = '''    def on_wake_fast(self) -> None:
        """唤醒瞬间的立即动作（由 WakeFastThread 调用，不经过主循环）。

        顺序特意是"先登录、后探测"：刚醒来 DNS 多半还没好，探测必失败，
        但网关是 IP 直连，登录请求往往 1 秒内就被接受。
        """
        now = time.monotonic()
        self._last_resume_mono = now
        self._last_resume_wall = time.time()
        self.after_wake = True
        self._wake_fast_left = int(self.cfg.get("monitor.wake_fast_probes", 12))
        self._wake_unknown_logged = False
        self._wake_preauth_ok = False
        self._wake_preauth_tries = 0
        self._wake_rearm_done = False
        self._wake_deadline = now + max(
            3.0, float(self.cfg.get("monitor.wake_preauth_window", 25)))
        self.checker.fast_probe = True
        self.checker.quick_auth = True
        try:
            self.stats.add_wake_event()
        except Exception:
            pass
        self._end_session("sleep")
        grace = float(self.cfg.get("monitor.wake_grace", 1))
        LOG.info("系统已唤醒（独立线程捕获），%ss 后抢连...", grace)
        if grace > 0:
            time.sleep(grace)
        if self._wake_preauth():
            LOG.info("唤醒抢连：网关已接受登录，等待探测确认")

'''
s = s.replace(anchor2, new_fn + anchor2, 1)

# 3) 启动/停止这个线程
anchor3 = '''        # 启动时先跑一次，避免"开机后干等 30 秒"
        self._tick(initial=True)'''
assert anchor3 in s
new3 = '''        # 独立唤醒抢连线程：与主循环解耦，醒来第一时间动作
        try:
            self._wake_thread = WakeFastThread(self)
            self._wake_thread.start()
        except Exception as exc:
            LOG.debug("唤醒抢连线程启动失败: %s", exc)

        # 启动时先跑一次，避免"开机后干等 30 秒"
        self._tick(initial=True)'''
s = s.replace(anchor3, new3, 1)

anchor4 = '''        self._end_session("program_exit")
        self.stats.save(force=True)
        self.watcher.stop()'''
assert anchor4 in s
new4 = '''        self._end_session("program_exit")
        self.stats.save(force=True)
        try:
            if getattr(self, "_wake_thread", None):
                self._wake_thread.stop()
        except Exception:
            pass
        self.watcher.stop()'''
s = s.replace(anchor4, new4, 1)

# 4) 初始化字段
anchor5 = "        self._last_selfcheck = 0.0         # 上次\"直接问 Portal 网关\"的时刻（节流用）"
assert anchor5 in s
s = s.replace(anchor5, anchor5 + "\n        self._wake_thread = None           # 独立唤醒抢连线程", 1)

io.open(p, "w", encoding="utf-8", newline="").write(s)
print("patched WakeFastThread")
