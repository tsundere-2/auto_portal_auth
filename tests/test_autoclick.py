#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tests/test_autoclick.py —— Portal 自动点击引擎的测试

运行：
    python tests/test_autoclick.py            # 全部测试
    python tests/test_autoclick.py -v

说明：
  * 打分逻辑的测试不需要浏览器，随时可跑。
  * 真实点击测试需要 selenium + Edge/Chrome；缺失时自动 skip。
  * 第一次运行会由 Selenium Manager 下载浏览器驱动，需要联网。
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import portal_autoclick as pac                      # noqa: E402
from auto_portal_auth import Config                 # noqa: E402
from fake_portal_server import FakePortalServer     # noqa: E402


def make_cfg(tmp: Path, **overrides) -> Config:
    data = {
        "browser_automation": {
            "enabled": True,
            "browser": "auto",
            "headless": True,
            "timeout": 40,
            "page_load_timeout": 20,
            "verify_interval": 1,
            "click_delay": 0.5,
            "settle_seconds": 0.8,
            "profile_dir": str(tmp / "profile"),
            "dump_dir": str(tmp / "dumps"),
            "dump_on_failure": True,
        }
    }
    for key, value in overrides.items():
        data["browser_automation"][key] = value
    return Config(data=data, path=tmp / "config.yaml")


class TestScoring(unittest.TestCase):
    """不打浏览器，纯打分逻辑。"""

    def _score(self, **cand) -> float:
        base = {"text": "", "id": "", "cls": "", "name": "", "onclick": "",
                "href": "", "type": "", "tag": "button", "visible": True,
                "disabled": False, "in_form": False}
        base.update(cand)
        return pac.score_candidate(base, pac.DEFAULT_BUTTON_TEXTS, pac.DEFAULT_DENY_TEXTS)

    def test_connect_button_wins(self):
        connect = self._score(text="连接", id="connect-btn")
        cancel = self._score(text="取消", id="cancel-btn")
        download = self._score(text="下载客户端")
        self.assertGreater(connect, 10)
        self.assertLess(cancel, 0)
        self.assertLess(download, 0)

    def test_login_and_english(self):
        self.assertGreaterEqual(self._score(text="登录"), 8)
        self.assertGreaterEqual(self._score(text="Sign in"), 8)
        self.assertGreaterEqual(self._score(text="一键登录"), 10)

    def test_hidden_or_disabled_penalised(self):
        self.assertLess(self._score(text="连接", visible=False), 0)
        self.assertLess(self._score(text="连接", disabled=True), 0)

    def test_submit_input(self):
        self.assertGreaterEqual(self._score(text="", type="submit", in_form=True), 5)

    def test_avoid_fake_positive(self):
        # 一个普通链接不该被当成认证按钮
        self.assertLess(self._score(text="了解更多", tag="a", cls="link"), 5)
        # 状态文字"已连接"不是按钮
        self.assertLess(self._score(text="已连接", tag="span", cls="status"), 5)

    def test_textless_image_button(self):
        """锐捷 ePortal：<a id="loginLink"><div></div></a>，按钮文字是背景图。"""
        real = self._score(
            tag="a", id="loginLink",
            onclick="this.className='loginButtonHKClicked_1';doauthen();")
        self.assertGreaterEqual(real, 15)
        self.assertGreater(real, self._score(tag="div", id="logininfo_hk",
                                             text="连接网络 校园网 记住密码"))

    def test_container_and_label_are_not_buttons(self):
        """整个登录框 / "连接网络"标题文字不能当成按钮点。"""
        container = self._score(tag="div", id="logininfo_hk",
                                text="连接网络 校园网 记住密码")
        label = self._score(tag="span", id="connectNetworkId", cls="span_2",
                            text="连接网络")
        self.assertLess(container, 5)
        self.assertLess(label, 5)

    def test_interactive_div_still_allowed(self):
        """div 上真的绑了 onclick 时不该被误伤。"""
        self.assertGreaterEqual(self._score(tag="div", text="连接",
                                            onclick="doLogin()"), 8)


@unittest.skipUnless(pac.selenium_available(), "未安装 selenium")
@unittest.skipUnless(pac.find_browser("auto")[0], "未找到 Edge/Chrome")
class TestBrowser(unittest.TestCase):
    """真实浏览器：识别 iframe 里的按钮、勾选条款、点击、验证联网。"""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp(prefix="apa_test_"))
        self.srv = FakePortalServer().__enter__()
        self.cfg = make_cfg(self.tmpdir)
        self.clicker = pac.PortalAutoClicker(self.cfg)

    def tearDown(self):
        self.srv.__exit__(None, None, None)
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_explain_finds_button_in_iframe(self):
        rows = self.clicker.explain(self.srv.url)
        self.assertTrue(rows, "没有采集到任何候选元素")
        texts = [r["text"] for r in rows]
        self.assertTrue(any("连接" in t for t in texts), f"未找到连接按钮: {texts[:10]}")
        best = max(rows, key=lambda r: r["score"])
        self.assertIn("连接", best["text"])
        self.assertGreaterEqual(best["score"], 5)
        self.assertTrue(best["would_click"])
        self.assertNotEqual(best["frame"], "top", "按钮应该在 iframe 里被找到")

    def test_click_ticks_terms_and_authenticates(self):
        result = self.clicker.click(self.srv.url, verify=lambda: self.srv.online)
        self.assertTrue(result.clicked, f"没有点击任何按钮: {result.error} {result.to_dict()}")
        self.assertTrue(result.success, f"点击后未确认联网: {result.to_dict()}")
        self.assertTrue(result.checkboxes, "没有勾选服务条款复选框")
        self.assertTrue(self.srv.online)
        self.assertTrue(self.srv.clicks, "后端没收到认证请求")
        self.assertTrue(self.srv.clicks[-1]["agreed"], "提交时条款未被勾选")

    def test_ruijie_textless_button(self):
        """锐捷 ePortal：按钮没有文字，周围还有"连接网络"标题干扰。"""
        url = self.srv.url.replace("/portal", "/ruijie")
        result = self.clicker.click(url, verify=None)
        self.assertTrue(result.clicked, f"没有点击任何按钮: {result.error} {result.to_dict()}")
        self.assertEqual(result.clicked_tag, "a", f"点错了元素: {result.to_dict()}")
        self.assertGreaterEqual(result.score, 15)
        self.assertTrue(result.success, f"点击后页面没有出现成功提示: {result.to_dict()}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
