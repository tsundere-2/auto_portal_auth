/**
 * background.js —— Service Worker
 *
 * 职责很轻：
 *   1. 收到 content script 的"已点击"消息后，在工具栏图标上显示 ✓（60 秒后清除）
 *   2. 把最近一次动作记录到 chrome.storage.local，供弹窗展示
 *
 * 注意：MV3 的 Service Worker 随时可能被浏览器回收，
 * 所以这里不保存需要长期存活的状态（全部落 storage）。
 */

const BADGE_CLEAR_MS = 60000;

chrome.runtime.onMessage.addListener((msg, sender) => {
  if (!msg || msg.type !== 'APA_RESULT') return;

  const tabId = sender.tab && sender.tab.id;

  // 工具栏角标：只对当前 tab 生效
  if (typeof tabId === 'number') {
    try {
      chrome.action.setBadgeText({ tabId, text: msg.ok ? '✓' : '…' });
      chrome.action.setBadgeBackgroundColor({
        tabId,
        color: msg.ok ? '#16a34a' : '#f59e0b'
      });
      setTimeout(() => {
        try {
          chrome.action.setBadgeText({ tabId, text: '' });
        } catch (e) { /* tab 可能已关闭 */ }
      }, BADGE_CLEAR_MS);
    } catch (e) { /* 忽略 */ }
  }

  chrome.storage.local.set({
    last: {
      ok: !!msg.ok,
      text: msg.text || '',
      score: msg.score || 0,
      url: (sender.tab && sender.tab.url) || '',
      title: (sender.tab && sender.tab.title) || '',
      at: Date.now()
    }
  });
});

// 首次安装时写入默认设置
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.sync.get(
    { enabled: true, autoClick: true, delay: 1200, maxAttempts: 5, allowHosts: [] },
    (s) => chrome.storage.sync.set(s)
  );
});
