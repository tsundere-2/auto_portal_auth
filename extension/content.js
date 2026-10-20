/**
 * content.js —— 在认证页里自动"勾选条款 + 点击连接/登录"
 *
 * 安全原则：扩展会注入到所有 http/https 页面，因此必须先判断
 * "这个页面像不像校园网认证页"，绝不能在 Gmail、银行等页面乱点。
 * 判定条件（满足其一 + 存在高可信按钮）：
 *   1. 主机名是内网 IP（10.x / 172.16-31.x / 192.168.x）
 *   2. URL / 标题 / 正文包含 portal、认证、上网、srun、eportal、drcom、wlan 等关键词
 *   3. 用户在弹窗里把当前站点加入了"总是启用"白名单
 */

(() => {
  if (window.__APA_EXT_LOADED__) return;
  window.__APA_EXT_LOADED__ = true;

  // ---------------- 可调参数（与 Python 版保持一致的口径） ----------------
  const BUTTON_TEXTS = {
    '同意并登录': 12, '同意并连接': 12, '同意并上网': 12, '同意并继续': 9,
    '一键登录': 10, '一键连接': 10, '一键上网': 10,
    '立即登录': 9, '立即连接': 9, '立即上网': 9,
    '点击登录': 9, '点击连接': 9, '点击上网': 9,
    '开始上网': 9, '免费上网': 8, '认证上网': 9,
    '连接': 8, '登录': 8, '登陆': 8, '认证': 7, '上网': 7,
    '确认': 4, '确定': 4, '继续': 3, '同意': 5,
    'access internet': 9, 'quick login': 10, 'click to connect': 9,
    'connect': 8, 'login': 8, 'log in': 8, 'sign in': 8, 'signin': 8,
    'authenticate': 8, 'authorize': 6,
    'confirm': 4, 'continue': 3, 'agree': 5, 'i agree': 7, 'accept': 4
  };

  const DENY_TEXTS = [
    '取消', '关闭', '返回', '退出', '断开', '注销', '下线', '帮助', '下载',
    '注册', '忘记', '重置', '修改', '语言', '切换', '客服', '公告', '详情',
    '了解更多', '常见问题', '使用说明', '客户端', '二维码', '扫码', '其他',
    '已连接', '已登陆', '已登录', '已认证', '已经连接', '已经登录', '已经认证',
    '当前在线', '已在线', '连接成功', '登录成功', '认证成功', '上网成功',
    'cancel', 'close', 'back', 'exit', 'logout', 'log out', 'sign out',
    'disconnect', 'help', 'download', 'register', 'sign up', 'forgot',
    'reset', 'language', 'english', 'more', 'faq', 'qrcode', 'scan',
    'already connected', 'already logged in', 'you are online', 'success'
  ];

  const ATTR_KEYWORDS = {
    connect: 3, login: 3, signin: 3, submit: 3, auth: 2,
    'connect-btn': 5, 'login-btn': 5, loginbutton: 5, 'submit-btn': 4,
    'btn-primary': 2, 'btn-success': 2, primary: 1,
    '连接': 3, '登录': 3, '认证': 2, '上网': 3
  };

  const TERMS_RE = /同意|已阅读|已同意|服务条款|服务协议|隐私政策|隐私|用户协议|我已|agree|terms|policy|privacy|accept/i;
  const PORTAL_RE = /portal|认证|上网|登录|登陆|校园网|网络接入|eportal|srun|drcom|wlan|hotspot|captive|wifi|welcome/i;

  const CANDIDATE_SEL = [
    'button', 'input[type="submit"]', 'input[type="button"]', 'input[type="image"]',
    'a', '[role="button"]', '[onclick]',
    '[class*="btn"]', '[class*="button"]', '[class*="login"]', '[class*="connect"]',
    '[class*="submit"]', '[id*="btn"]', '[id*="login"]', '[id*="connect"]', '[id*="submit"]'
  ].join(',');

  const DEFAULTS = { enabled: true, autoClick: true, delay: 1200, maxAttempts: 5, allowHosts: [] };
  let settings = { ...DEFAULTS };
  let clicked = false;
  let attempt = 0;
  let observer = null;
  let timers = [];

  // ---------------- 工具 ----------------
  const log = (...a) => console.debug('[PortalAutoConnect]', ...a);

  function isVisible(el) {
    try {
      const r = el.getBoundingClientRect();
      if (!r || r.width < 2 || r.height < 2) return false;
      const s = getComputedStyle(el);
      if (!s) return true;
      if (s.visibility === 'hidden' || s.display === 'none') return false;
      if (parseFloat(s.opacity || '1') === 0) return false;
      return true;
    } catch (e) { return false; }
  }

  function textOf(el) {
    const t = el.innerText || el.value || el.getAttribute('aria-label') ||
              el.getAttribute('title') || el.getAttribute('alt') || '';
    return (t + '').replace(/\s+/g, ' ').trim();
  }

  function score(el) {
    const text = textOf(el);
    const tl = text.toLowerCase();
    const attrs = [el.id || '', el.className || '', el.getAttribute('name') || '',
                   el.getAttribute('onclick') || '', el.getAttribute('href') || '']
                   .join(' ').toLowerCase();
    let s = 0;
    if (!isVisible(el)) s -= 100;
    if (el.disabled || el.getAttribute('aria-disabled') === 'true') s -= 60;

    let best = 0;
    for (const [kw, w] of Object.entries(BUTTON_TEXTS)) {
      if (tl.includes(kw)) best = Math.max(best, w + (tl === kw ? 2 : 0));
    }
    s += best;

    for (const [kw, w] of Object.entries(ATTR_KEYWORDS)) {
      if (attrs.includes(kw)) s += w;
    }
    const type = (el.getAttribute('type') || '').toLowerCase();
    if (type === 'submit') s += 3;
    if (el.tagName === 'BUTTON') s += 2;
    if (el.closest && el.closest('form')) s += 2;
    if (text.length > 40) s -= 3;
    for (const kw of DENY_TEXTS) {
      if (tl.includes(kw)) s -= 14;
    }
    return Math.round(s * 10) / 10;
  }

  function isPrivateHost(host) {
    if (!host) return false;
    if (/^10\./.test(host)) return true;
    if (/^192\.168\./.test(host)) return true;
    const m = host.match(/^172\.(\d+)\./);
    if (m) { const n = +m[1]; if (n >= 16 && n <= 31) return true; }
    return false;
  }

  function looksLikePortal() {
    const host = location.hostname || '';
    if (Array.isArray(settings.allowHosts) && settings.allowHosts.includes(host)) return true;
    if (isPrivateHost(host)) return true;
    const hay = [location.href, document.title, (document.body ? document.body.innerText.slice(0, 4000) : '')].join(' ');
    return PORTAL_RE.test(hay);
  }

  // ---------------- 勾选条款 ----------------
  function tickTerms() {
    const ticked = [];
    const boxes = document.querySelectorAll('input[type="checkbox"],[role="checkbox"]');
    for (const box of boxes) {
      if (box.checked === true) continue;
      if (box.getAttribute('aria-checked') === 'true') continue;
      if (box.dataset.apaTicked === '1') continue;

      // 找到与之关联的说明文字
      let label = '';
      try {
        const lab = box.closest('label');
        if (lab) label = lab.innerText || '';
        if (!label && box.id) {
          const l2 = document.querySelector('label[for="' + CSS.escape(box.id) + '"]');
          if (l2) label = l2.innerText || '';
        }
        if (!label && box.parentElement) label = box.parentElement.innerText || '';
      } catch (e) {}

      if (!TERMS_RE.test(label) && label.trim().length > 0) continue; // 只点条款类
      try {
        box.click();
        box.dataset.apaTicked = '1';
        ticked.push(label.trim().slice(0, 60) || 'checkbox');
        log('已勾选条款:', label.trim().slice(0, 60));
      } catch (e) {}
    }
    return ticked;
  }

  // ---------------- 找按钮并点击 ----------------
  function findBest() {
    let best = null;
    let bestScore = -Infinity;
    let nodes = [];
    try { nodes = document.querySelectorAll(CANDIDATE_SEL); } catch (e) { return null; }

    for (const el of nodes) {
      if (el.dataset && el.dataset.apaClicked === '1') continue;
      const s = score(el);
      if (s > bestScore) { bestScore = s; best = { el, s, text: textOf(el) }; }
    }
    return (best && bestScore >= 5) ? best : null;
  }

  function clickBest(force) {
    const found = findBest();
    if (!found) return false;
    const { el, s, text } = found;
    try { el.scrollIntoView({ block: 'center' }); } catch (e) {}
    try { el.focus(); } catch (e) {}
    try {
      el.click();
    } catch (e) {
      try {
        el.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, view: window }));
      } catch (e2) { return false; }
    }
    if (el.dataset) el.dataset.apaClicked = '1';
    clicked = true;
    log('已点击:', text || el.tagName, 'score=', s);
    report(true, (text || el.tagName).slice(0, 80), s);
    return true;
  }

  // ---------------- 与后台通信 ----------------
  function report(ok, text, s) {
    try {
      chrome.runtime.sendMessage({ type: 'APA_RESULT', ok, text: text || '', score: s || 0 });
    } catch (e) {}
  }

  // ---------------- 主流程 ----------------
  function run(force) {
    if (!settings.enabled) return;
    if (!force && clicked) return;
    if (!looksLikePortal()) { log('页面不像认证页，跳过'); return; }

    tickTerms();
    if (clickBest(force)) return;

    attempt += 1;
    if (attempt >= settings.maxAttempts) { log('尝试次数用尽，停止'); return; }
    // 页面可能还在渲染（很多 Portal 用 JS 动态插入按钮）
    const t = setTimeout(() => run(force), 1500);
    timers.push(t);
  }

  function start() {
    const t = setTimeout(() => run(false), Math.max(300, settings.delay));
    timers.push(t);

    // 监听动态渲染：页面加载完成后再出现按钮也能点
    try {
      observer = new MutationObserver(() => {
        if (clicked || !settings.autoClick) return;
        clearTimeout(observer._t);
        observer._t = setTimeout(() => run(false), 600);
      });
      observer.observe(document.documentElement, { childList: true, subtree: true });
      setTimeout(() => { try { observer.disconnect(); } catch (e) {} }, 45000);
    } catch (e) {}
  }

  chrome.storage.sync.get(DEFAULTS, (s) => {
    settings = { ...DEFAULTS, ...(s || {}) };
    if (settings.enabled && settings.autoClick) start();
  });

  // 弹窗里点"立即执行" / 查询状态
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (!msg || !msg.type) return;
    if (msg.type === 'APA_CLICK_NOW') {
      attempt = 0;
      run(true);
      sendResponse({ ok: true, clicked, portal: looksLikePortal(), href: location.href });
      return true;
    }
    if (msg.type === 'APA_STATUS') {
      let best = null;
      if (looksLikePortal()) { const b = findBest(); best = b ? { text: b.text, score: b.s } : null; }
      sendResponse({
        portal: looksLikePortal(),
        clicked,
        best,
        title: document.title,
        href: location.href
      });
      return true;
    }
  });
})();
