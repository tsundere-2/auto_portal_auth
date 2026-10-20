/**
 * popup.js —— 弹窗逻辑
 *
 * 功能：
 *   - 开关自动点击、调整延迟
 *   - 显示当前页面是否为认证页、找到的最佳按钮
 *   - "立即执行一次"（对调试未知认证页特别有用：能直接看到识别到哪个按钮、得分多少）
 *   - "本网站总是启用"（把当前域名加入白名单，适配内网域名的 Portal）
 */

const $ = (id) => document.getElementById(id);
const DEFAULTS = { enabled: true, autoClick: true, delay: 1200, maxAttempts: 5, allowHosts: [] };

let activeTabId = null;
let activeHost = '';

function setStatus(html, cls) {
  const el = $('status');
  el.innerHTML = html;
  el.className = cls || '';
}

/** 向当前标签页的 content script 发消息；没有 content script 时返回 null */
function sendToTab(msg) {
  return new Promise((resolve) => {
    if (activeTabId == null) return resolve(null);
    chrome.tabs.sendMessage(activeTabId, msg, (resp) => {
      void chrome.runtime.lastError;   // 页面不支持注入时会有 lastError，忽略即可
      resolve(resp || null);
    });
  });
}

async function refreshStatus() {
  const s = await sendToTab({ type: 'APA_STATUS' });
  if (!s) {
    setStatus(
      '当前页面无法注入脚本（<b>浏览器内部页面</b>或扩展刚安装尚未刷新）。<br>' +
      '请在认证页按 <b>F5</b> 后再试。', 'warn');
    return;
  }
  if (!s.portal) {
    setStatus('当前页面<b>不像</b>校园网认证页，扩展不会自动点击。', 'muted');
    return;
  }
  if (s.clicked) {
    setStatus('本页已自动点击过认证按钮。', 'ok');
    return;
  }
  if (s.best) {
    setStatus(
      `已识别认证页，准备点击：<br><b>${escapeHtml(s.best.text || '(无文本按钮)')}</b> ` +
      `<span class="muted">得分 ${s.best.score}</span>`, 'ok');
  } else {
    setStatus('是认证页，但<b>没有找到可信的按钮</b>（得分低于阈值）。<br>' +
      '可点击下方按钮强制扫描一次。', 'warn');
  }
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function renderLast(last) {
  if (!last) return;
  const t = new Date(last.at || Date.now()).toLocaleString();
  $('last').innerHTML =
    `${last.ok ? '<span class="ok">✓ 已点击</span>' : '<span class="warn">… 尝试过</span>'} ` +
    `「${escapeHtml(last.text || '')}」<br><span class="muted">${t} · ${escapeHtml(last.title || last.url || '')}</span>`;
}

// ---------------- 初始化 ----------------
chrome.storage.sync.get(DEFAULTS, (s) => {
  const cfg = { ...DEFAULTS, ...(s || {}) };
  $('enabled').checked = !!cfg.enabled;
  $('delay').value = cfg.delay;

  chrome.storage.local.get({ last: null }, (r) => renderLast(r.last));

  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs && tabs[0];
    if (!tab) return;
    activeTabId = tab.id;
    try { activeHost = new URL(tab.url).hostname; } catch (e) { activeHost = ''; }
    $('allow').textContent = activeHost ? `本网站总是启用（${activeHost}）` : '本网站总是启用';
    $('allow').disabled = !activeHost;
    refreshStatus();
  });
});

// 开关 / 延迟
$('enabled').addEventListener('change', (e) => {
  chrome.storage.sync.set({ enabled: e.target.checked });
  if (e.target.checked) refreshStatus();
});

$('delay').addEventListener('change', (e) => {
  const v = Math.max(0, Math.min(30000, parseInt(e.target.value, 10) || 0));
  e.target.value = v;
  chrome.storage.sync.set({ delay: v });
});

// 立即执行
$('run').addEventListener('click', async () => {
  setStatus('正在执行…');
  const r = await sendToTab({ type: 'APA_CLICK_NOW' });
  if (!r) {
    setStatus('当前页面无法注入脚本，请刷新认证页后重试。', 'warn');
    return;
  }
  if (!r.portal) {
    setStatus('当前页面不像认证页，未执行。', 'muted');
    return;
  }
  setStatus(r.clicked ? '已点击认证按钮，请观察是否恢复上网。' :
    '已执行，但没有找到可点击的按钮。', r.clicked ? 'ok' : 'warn');
  setTimeout(refreshStatus, 1200);
});

// 加入白名单
$('allow').addEventListener('click', () => {
  if (!activeHost) return;
  chrome.storage.sync.get(DEFAULTS, (s) => {
    const list = Array.isArray(s.allowHosts) ? s.allowHosts.slice() : [];
    if (!list.includes(activeHost)) list.push(activeHost);
    chrome.storage.sync.set({ allowHosts: list }, () => {
      setStatus(`已把 <b>${escapeHtml(activeHost)}</b> 加入白名单，刷新页面后生效。`, 'ok');
    });
  });
});
