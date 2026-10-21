# AutoPortalAuth — 校园网 Portal 自动认证守护程序

> 解决"睡眠唤醒 / 开机后必须打开浏览器才能上网"的问题：主动探测 → 发现被 Portal 拦截 → 自动触发认证 → **自动勾选条款并点掉"连接/登录"按钮** → 恢复网络，并统计空闲超时规律做**心跳保活**，把掉线消灭在发生之前。

---

## 目录

- [它是怎么工作的](#它是怎么工作的)
- [快速开始](#快速开始)
- [命令一览](#命令一览)
- [配置文件重点项](#配置文件重点项)
- [自动点击认证按钮（三套方案）](#自动点击认证按钮三套方案)
- [关键实现细节](#关键实现细节)
  - [1. 如何判断"未连接" vs "需要认证"](#1-如何判断未连接-vs-需要认证)
  - [2. 如何识别 Portal 认证页面](#2-如何识别-portal-认证页面)
  - [3. 如何适配锐捷 / Dr.COM / 深澜等不同认证系统](#3-如何适配锐捷--drcom-深澜等不同认证系统)
  - [4. 网络异常与重试策略](#4-网络异常与重试策略)
  - [5. 唤醒 / 网络变化监听](#5-唤醒--网络变化监听)
  - [6. 如何最小化资源占用](#6-如何最小化资源占用)
- [开机自启](#开机自启)
- [故障排查](#故障排查)
- [安全提示](#安全提示)

---

## 它是怎么工作的

校园网 Portal 认证的本质：

| 现象 | 原因 |
| --- | --- |
| 睡醒后网线插着、也有 IP，但必须打开浏览器才能上网 | 认证服务器在**会话空闲超时**后清理了会话，但空闲超时**不会**通知客户端 |
| 拔掉网线再插上反而能自动恢复 | 物理链路闪断会触发链路层重新协商，认证系统重新下发认证页 |

所以"自动认证"的关键不是去猜服务器什么时候超时，而是**主动、周期性地验证自己还能不能上网**，一旦发现不能，就立刻重放一次"用户打开浏览器"的动作。

程序的状态机：

```
                     链路 down / 无 IP
        ┌────────────────────────────────────┐
        │                                    ▼
   ┌────────────┐   探测被重定向/内容不符   ┌──────────────┐
   │INTERNET_OK │ ────────────────────────▶ │PORTAL_REQUIRED│
   │  正常上网   │ ◀──────────────────────── │  需要认证     │
   └────────────┘      认证成功 / 自动登录    └──────────────┘
        │                                          ▲
        │ 保活心跳(默认按空闲超时自动推算)            │ 重试(指数退避)
        └──────────────────────────────────────────┘
```

一次"发现 → 认证 → 恢复"的完整流程：

1. 每 `monitor.interval` 秒（默认 30s）向 `http://www.msftconnecttest.com/connecttest.txt` 等目标发一次 HTTP 请求；
2. 若返回 3xx 重定向、状态码不符、或正文不含预期内容 → 判定**被 Portal 拦截**，抓取认证页真实地址与页面正文；
3. 对页面做厂商指纹识别，然后按顺序尝试：**静默自动登录** → **自定义触发命令** → **Selenium 自动勾选条款并点击"连接/登录"** → **HTTP GET 戳认证页** → **打开默认浏览器**；
4. 认证后重新探测，确认真的能上网了才算成功（否则指数退避重试并累计失败次数）；
5. 全程写入日志、`data/stats.json`（统计）、`data/state.json`（当前状态快照）。

---

## 快速开始

### Windows

```bat
:: 双击 install.bat 即可（它只是一个 ASCII/CRLF 极简启动器，真正的安装在 install.py）
install.bat
```

脚本会自动：检查 Python → 安装依赖 → 生成 `config.yaml` → 自检 → 试运行 → 询问是否安装开机自启。

也可以跳过批处理直接运行安装器（参数更全）：

```bat
python install.py                                     :: 交互式安装
python install.py --autostart no                      :: 只装依赖和配置，不装自启
python install.py --autostart yes --method task --start-now
python install.py --help
```

> `install.bat` 里**只有 ASCII 字符、只有 CRLF 换行、也没有 `chcp`**，这是刻意为之：
> cmd.exe 读取纯 LF 的批处理会解析错乱，而在批处理里切换代码页后它会按字节偏移
> 继续读脚本，从而"吃掉"下一行的首字符（`python` → `ython`）。中文提示全部放在
> `install.py`（Python 处理 UTF-8 没有问题），由 Python 自己去设置控制台代码页。
> 如果你要修改 `install.bat`，请保持这两条约束。

### Linux / macOS

```bash
chmod +x install.sh
./install.sh
```

### 手动安装（三行）

```bash
pip install -r requirements.txt
python auto_portal_auth.py selftest     # 自检指纹识别
python auto_portal_auth.py run          # 前台常驻运行
```

后台常驻（Windows 无窗口）：

```bat
pythonw auto_portal_auth.py run
```

---

## 命令一览

| 命令 | 说明 |
| --- | --- |
| `run` | 常驻守护运行（默认命令）。支持 `--interval 20` 覆盖巡检周期、`--no-lock` 跳过多实例检查 |
| `once` | 单次检测并退出；默认会尝试触发认证，`--no-trigger` 只检测。退出码：`0`=正常 `1`=未知 `2`=需要认证 `3`=链路断开 |
| `status` | 打印当前状态 JSON（含探测明细、认证页地址、厂商指纹） |
| `stats` | 打印统计：总在线时长、会话数、断连次数、认证成功率、最近会话 |
| `analyze` | 分析观测到的**空闲超时**，给出建议的保活间隔 |
| `install` | 安装开机自启，`--method registry\|startup\|task\|systemd\|launchd`，`--start-now` 立即启动 |
| `uninstall` | 卸载开机自启 |
| `autoclick` | 打开认证页 → 自动勾选条款 → 点击"连接/登录" → 验证联网。`--explain` 只打印候选元素打分（调参用）、`--headed` 显示窗口、`--url` 指定页面、`--selector` 追加选择器 |
| `driver` | 检查浏览器与驱动；`--download` 预下载驱动（首次需联网）。纯本地命令，不依赖 requests / PyYAML，并会打印驱动版本与当前解释器路径 |
| `install-extension` | 打开浏览器扩展管理页并显示 `extension/` 目录（方案 C） |
| `selftest` | 内置自检：用锐捷 / Dr.COM / 深澜 / H3C 等样例页面验证指纹识别 |

通用参数：`-c/--config 路径`、`-v/--verbose`、`--log-level DEBUG`。

---

## 配置文件重点项

完整说明见 [`config.yaml`](config.yaml) 内的注释，最常改的几项：

```yaml
monitor:
  interval: 30            # 正常时巡检周期；想更"灵敏"可改 15，省电可改 60

auth:
  open_browser: true      # 是否打开默认浏览器（多数 Portal 必须由浏览器完成 JS 认证）
  auto_login:
    enabled: false        # ★ 填好账号密码并改为 true，即可全自动、无人值守
    username: "20230001"
    password: "your-password"
  keepalive:
    enabled: true
    interval: 0           # 0 = 自动（依据 stats 里的空闲超时中位数 × 0.6）

browser_automation:       # ★ 自动勾选条款 + 点击"连接/登录"按钮
  enabled: true
  headless: auto          # auto = 先无头，失败再显示窗口
  button_texts: []        # 识别不到按钮时，在这里补充按钮文本关键词

notification:
  enabled: true           # 认证成功/失败时的系统通知
```

> **推荐做法**：先只开 `open_browser`（默认），跑几天让程序统计出校园网的空闲超时时间；
> 执行 `python auto_portal_auth.py analyze` 看到建议值后，把 `auth.keepalive.interval`
> 设为略小于超时时间的值，掉线率会显著下降。若你的 Portal 允许脚本登录（多数锐捷/深澜的
> `/eportal`、`/srun_portal` 接口都可以），再填账号密码开启 `auto_login`。

---

## 自动点击认证按钮（三套方案）

### 问题在哪

程序已经能在唤醒后自动打开认证页，但页面上还差"最后一下"：

- 认证页不是标准的用户名/密码表单，而是一个 **"连接 / 登录 / 一键上网"按钮**（MAC 无感认证常见）；
- 按钮旁可能有 **"我已阅读并同意《服务条款》"复选框**，不勾选时后端直接拒绝；
- 有的 Portal 还会弹 `confirm`/`alert`，或用 `window.open` 开新窗口放"确认"按钮；
- 页面上的按钮是 JS 动态渲染的，打开瞬间还不存在。

`portal_autoclick.py` 就是为这"最后一下"写的：**真正驱动浏览器去勾选和点击**，
而不是再打开一个页面让用户自己点。

### 方案 A：Selenium 浏览器自动化（默认启用）

一次自动点击的完整流程：

```
启动浏览器（默认无头，失败自动换可见窗口）
        │
        ├─ 打开认证页（允许自签证书、绕过系统代理）
        ├─ 逐层扫描 DOM：document → iframe/frame（最多 3 层）→ Shadow DOM
        ├─ 勾选"同意/我已阅读/服务条款/隐私政策"类复选框（已勾选的绝不重复点）
        ├─ 候选元素打分：文本权重 + id/class/name 关键词 + type=submit + 是否在表单内
        │     减去：取消/退出/断开/下载/注册/忘记密码/已连接/不可见/禁用
        ├─ 分数 ≥ score_threshold(5) 才点击；否则宁可不点，避免乱点
        ├─ 处理 alert/confirm，跟进点击后新出现的窗口并继续找"确认"
        └─ 轮询真实联网状态（复用主程序的探测），确认成功才算完成
```

关键设计：

| 设计 | 原因 |
| --- | --- |
| `headless: auto` | 先无头（不打扰用户、省资源）；有些 Portal 的 JS 在无头下不工作，失败后自动换可见窗口重试一次 |
| 专用 `profile_dir` | 使用 `data/browser_profile`，保留"记住我"和 MAC 认证所需状态，且**不碰你日常浏览器的配置**（不会因为 Chrome 正在运行而冲突） |
| 分数阈值 + 否定词 | 认证页上常有"取消/下载客户端/找回密码"，乱点会导致更麻烦的后果 |
| 失败退避 | 连续失败 `failure_threshold` 次后暂停 `failure_cooldown` 秒，期间退回"打开浏览器"兜底，避免每次巡检都启动浏览器 |
| 失败留证 | 自动保存截图 + HTML 到 `data/autoclick/`，方便补充关键词或选择器 |

### 方案 B：HTTP 直连（`auth.auto_login`）

适用于标准表单 Portal（锐捷 ePortal、深澜 srun 等）。本次增强了三点：

1. **提交按钮的 `name/value` 也会一起提交** —— 很多 Portal 会校验"是哪个按钮提交的"，
   漏掉它就会一直返回"请点击连接"；
2. `<button>` 标签也会被解析（以前只解析 `<input>`）；
3. **未勾选的复选框不再提交**，避免后端认为"未同意条款"；
4. 页面**没有表单**时直接跳过（MAC 无感认证页只有一个按钮），不再白等 `verify_timeout` 秒。

### 方案 C：浏览器扩展（`extension/`，最轻量）

不需要 Python、不需要驱动，认证页一打开就自动勾选并点击：

```bat
python auto_portal_auth.py install-extension
```

它会打开浏览器的扩展管理页和 `extension/` 目录，然后：
**开发人员模式 → 加载解压缩的扩展 → 选择该目录**（只需一次）。

扩展有三道安全闸门，避免在别的网站乱点：内网 IP / 认证关键词 / 用户白名单，
且按钮必须打分 ≥ 5、每个元素只点一次。详见 [`extension/README.md`](extension/README.md)。

### 三套方案怎么选

| | A. Selenium | B. HTTP 直连 | C. 浏览器扩展 |
| --- | --- | --- | --- |
| 依赖 | selenium + 浏览器驱动 | 无 | 无 |
| 首次准备 | `driver --download`（需联网） | 无需 | 手工加载一次扩展 |
| 速度 | 3–10 秒 | < 1 秒 | 页面打开即点 |
| 能处理"连接"按钮 | ✅ | ❌ | ✅ |
| 能处理复选框/弹窗/iframe | ✅ | 部分 | ✅ |
| 能验证真的联网了 | ✅ | ✅ | ❌（只看页面） |

**推荐组合**：主程序开方案 A；同时装上扩展 C 作为双保险。
即使某天驱动下载失败或 Portal 改版，扩展依然会把按钮点掉。

### 命令

```bat
:: 0) 首次：预下载浏览器驱动（必须在能上网时做一次，之后离线可用）
python auto_portal_auth.py driver --download

:: 1) 看看你的认证页能不能被识别（只打分，不点击）★ 最有用
python auto_portal_auth.py autoclick --explain

:: 2) 立即执行一次（会真的打开浏览器点击，并验证联网）
python auto_portal_auth.py autoclick

:: 3) 想看着它点（调试用）
python auto_portal_auth.py autoclick --headed --keep-open

:: 4) 指定页面 / 追加选择器
python auto_portal_auth.py autoclick --url http://10.0.0.1/portal --selector "#loginBtn"
```

`--explain` 的输出长这样（分数、是否会被点击、所在 frame、元素文本与属性）：

```
     分数  点击   frame      元素         文本 / 属性
------------------------------------------------------------------------------------------
   20.0  YES  top>0      <button  > '连接'  id='connect-btn' cls=''
  -12.0  -    top        <button  > '取消'  id='cancel-btn' cls='cancel'
  -28.0  -    top        <a       > '下载客户端'  id='' cls='dl'
```

### 识别不到按钮怎么办

按顺序尝试：

1. **看打分表**：`autoclick --explain`。如果目标按钮分数低于 5，把它文本里的独特词加进配置：

   ```yaml
   browser_automation:
     button_texts: ["我要上网", "立即认证"]     # 权重 9
   ```

2. **按钮没有文本**（纯图标/图片）：加 CSS 选择器（权重按属性计算）：

   ```yaml
   browser_automation:
     extra_button_selectors: ["#my-login-btn", ".auth-area .go"]
   ```

3. **误点到别的元素**：把它的文本加入否定词：

   ```yaml
   browser_automation:
     button_deny_texts: ["注销", "重新登录"]
   ```

4. **看现场**：失败时 `data/autoclick/fail-*.png` 与 `fail-*.html` 保存了截图和页面源码，
   把 HTML 发出来即可针对性地补规则。

5. **页面在 iframe 里但没被扫到**：确认 `max_frame_depth`（默认 3）足够，或直接用
   `--selector` 指定。

也可以完全关掉自动点击（回到旧行为）：

```yaml
browser_automation:
  enabled: false
```

### 需要输入账号密码的页面（锐捷 ePortal 等）

有些 Portal 不是"点一下就过"，而是要真的填账号密码再点登录。开启
`fill_credentials` 后，自动点击会在**页面存在密码框**时，把
`auth.auto_login` 里的账号密码填进去再点按钮：

```yaml
auth:
  auto_login:
    enabled: true            # 注意：这里要 true，填表才有账号可用
    username: "25124308"
    password: "你的密码"

browser_automation:
  fill_credentials: true     # 默认就是 true
```

实现细节（针对锐捷 ePortal 这类页面）：

- 输入框默认是 `display:none`，只显示只读的"用户名/密码"占位提示；
  脚本会先聚焦 `#pwd_tip` 把真实输入框唤出来，再写入。
- 页面用 `$("#username").attr("value")` 做非空校验，所以脚本同时写
  `el.value` 和 `value` 属性，并派发 `input/change/keyup/blur` 事件。
- 账号密码**只**来自 `auth.auto_login`，不会去猜、不会填到没有密码框的页面。
- 日志只记录账号，**从不**打印密码。

### 与主程序的执行顺序

`AuthTrigger.trigger()` 的尝试顺序（前一步成功就停止）：

```
1. auth.auto_login（HTTP 表单；锐捷 ePortal 由页面 JS 认证，会自动跳过）
2. auth.trigger_commands（自定义命令）
3. browser_automation（Selenium 填账号密码 + 勾选 + 点击）   ← 新增
4. HTTP GET 认证页（建立会话）
5. 打开默认浏览器（最后的兜底）
```

第 3 步成功后会**跳过**第 4、5 步，因此不会再多弹一个浏览器窗口。
若第 3 步点了但没确认联网，仍会执行第 4、5 步，保证你能看到页面并手动收尾。

---

## 关键实现细节

### 1. 如何判断"未连接" vs "需要认证"

分两层判断，先看链路层，再看应用层（`NetworkChecker.check()`）：

**第一层：物理链路 + IP**

用 `psutil` 枚举所有网卡：

```python
for name, st in psutil.net_if_stats().items():
    if not st.isup:                continue   # 网卡未启用 / 网线未插
    if name 命中 ignore_interfaces: continue   # 排除虚拟网卡/回环
    for a in psutil.net_if_addrs()[name]:
        if a.family != socket.AF_INET:      continue
        if a.address.startswith(("127.", "169.254.")):
            continue                        # 回环 / DHCP 失败的自动私有地址
        ...收集有效 IPv4...
```

- 没有任何可用网卡 → `LINK_DOWN`（网线未插 / 网卡禁用）
- 有网卡但没拿到有效 IP（只有 `169.254.x.x`）→ `NO_IP`（DHCP 未完成，常见于刚插上网线或唤醒瞬间）

> 这两个状态都**不会**去触发认证 —— 此时认证服务器根本联系不上，触发只会浪费资源。程序会以较短的
> `monitor.link_down_interval`（默认 5s）轮询，等链路就绪后再进入应用层探测。

**第二层：应用层连通性**

链路正常时，向多个"已知内容"的探测目标发 HTTP 请求（默认微软 `connecttest.txt`、小米
`generate_204`、Google `generate_204`）。**只要有一个目标通过，就认为能上网**（`INTERNET_OK`）；
若出现重定向 / 状态码不符 / 内容不符 → `PORTAL_REQUIRED`；全部超时且 DNS 也解析失败 →
`UNKNOWN`（可能是上游故障、DNS 被劫持而非 Portal 等）。

**为什么用 HTTP 而不是 ping？** Portal 拦截发生在应用层：ping（ICMP）和 DNS 常常是放行的，
只有 HTTP 请求才会被重定向到认证页。所以 ping 通不等于能上网，必须发 HTTP。

### 2. 如何识别 Portal 认证页面

`probe_target()` 用 `allow_redirects=False` 拿到首发响应，依次判定：

| 判据 | 说明 |
| --- | --- |
| **HTTP 3xx** | 出现 `Location` 重定向，几乎可以确定是 Portal。随后用 `_follow_redirects()` 手动跟随（默认最多 5 跳、带环路检测）拿到认证页真实地址 |
| **状态码不符** | 期望 `204` 却收到 `200` —— 典型的"DNS 劫持 + 返回认证页"形态 |
| **内容不符** | 期望正文含 `Microsoft Connect Test`，实际是登录页 HTML |
| **正文特征** | 认证页里通常有 `<form>` 表单、密码框、`登录/认证` 等字样，用于二次确认 |

拿到认证页后，进一步解析并保存证据：

- `guess_vendor()` 做**厂商指纹识别**（见下一节）；
- `_FormParser` 提取所有 `<form>` 的 `action/method` 以及每个 `input` 的 `name/type/value`；
- `_MetaRefreshParser` 提取 `<meta http-equiv="refresh" content="0;url=...">` 跳转（一些 Portal 用 JS/JS 之前的 meta 跳转）；
- `_TitleParser` 取页面标题，作为指纹与日志的可读证据。

这些信息全部写进 `data/state.json` 和日志，例如：

```json
{
  "state": "portal_required",
  "portal_url": "http://10.10.10.1/srun_portal_pc?ac_id=1&wlanuserip=10.1.2.3",
  "fingerprint": {
    "vendor": "srun", "confidence": 0.8,
    "evidence": ["srun:2", "url_param:wlanuserip", "form_fields:3"],
    "login_form": { "action": "/srun_portal_pc", "method": "post",
                    "fields": [ {"name": "username", "type": "text", "value": ""}, ... ] }
  }
}
```

### 3. 如何适配锐捷 / Dr.COM / 深澜等不同认证系统

采用"**正则指纹库 + 权重打分 + 通用兜底**"的策略，而不是给每家写死一套流程，
因为同一个厂商在不同学校会定制页面/接口，硬编码反而更脆弱。

内置指纹库（`PORTAL_SIGNATURES`）：

| 厂商 | 关键特征 |
| --- | --- |
| 深澜 srun | `srun`、`深澜`、`/srun_portal`、`ac_domain`、`srunuser` |
| 锐捷 Ruijie | `ruijie`、`锐捷`、`/eportal/`、`wlan.ruijie`、`RG-eportal` |
| Dr.COM | `drcom`、`Dr.COM`、`城市热点`、`/drcom/` |
| H3C | `h3c`、`华三`、`/portal/login`、`PortalServer`、`iMC` |
| 华为 | `huawei`、`华为`、`agilecontroller` |
| 深信服 | `sangfor`、`深信服`、`/ac_portal/` |
| 通用兜底 | `认证`、`portal`、`登录`、`login`、`上网` |

打分方式：`score = 权重 × (1 - 0.5**命中种类数)`，命中越多越可信（收敛到权重上限），
取最高分作为判定结果，并记录 `evidence` 便于人工核对。命中置信度写入日志，
也用于自动登录时的决策。

**认证动作的通用化处理**（`AuthTrigger`）——按"从静默到显式"的顺序：

1. **自动填表登录**（最强，需在配置里填账号密码）：
   - 直接使用指纹识别出的 `<form>`：`action` 拼到认证页 URL 上，`method` 按页面声明（GET/POST）；
   - 字段映射用**关键字猜测**：字段名含 `user/name/account/acct/login/sid/uid` → 填用户名；
     含 `pass/pwd/password/secret` → 填密码；`type=hidden` 的隐藏域（如 `lt`、`execution`、`nasip`）
     **原样回传**；
   - 自动补上 URL 查询串里的 Portal 协议参数（`wlanuserip`、`wlanacname`、`nasip`、`ac_id` 等，
     锐捷/深澜都依赖这些）；
   - 可在 `auto_login.extra_fields` 里补任意字段，适配学校定制接口。
2. **自定义触发命令**：`auth.trigger_commands` 里可以放任意命令，支持 `{portal_url}`、`{state}` 占位符，
   用于对接学校自带的登录脚本。
3. **HTTP GET 认证页**：部分 Portal 收到请求就下发/刷新会话，等价于"用户打开了一次网页"。
4. **打开默认浏览器**：最通用、最可靠的兜底 —— 认证页里的 JS 会完成剩余动作，
   用户最多点一次"登录"。同一 URL 有 `browser_cooldown`（默认 90s）冷却，避免疯狂弹窗。

每种方式执行后都会**重新探测验证**，只有真正能上网了才记录为成功 —— 避免"假成功"。

### 4. 网络异常与重试策略

- **分层退避**：`INTERNET_OK` 30s 巡检；`PORTAL_REQUIRED` 8s 起步并按
  `min(base × 2^失败次数, backoff_max)` 指数退避（最大 300s），避免把认证服务器刷爆或触发风控；
  `LINK_DOWN/NO_IP` 5s 快轮询（等网线/DHCP）。
- **异常隔离**：所有 HTTP 探测都带 `(connect, read)` 双超时（默认 3s/5s），任何
  `requests` 异常都被转成 `ProbeResult(kind="error")` 并记录，绝不会让主循环崩溃。
  多个探测目标互为备份：Google 被墙不影响，只要微软/小米任一通过就算正常。
- **忽略系统代理**：`session.trust_env = False`。否则环境变量里的 `HTTP_PROXY`
  会把探测请求转发给代理，就看不到 Portal 的重定向了（这是很常见的"检测不灵"原因）。
- **原子写文件**：`stats.json` / `state.json` 都先写 `.tmp` 再 `replace()`，
  断电或强杀进程也不会写坏文件；统计写盘还有 5 秒节流。
- **单实例锁**：`data/auto_portal_auth.lock` 记录 PID，启动时用 `psutil.pid_exists()` 校验；
  发现陈旧锁（进程已死）会自动接管。
- **信号处理**：捕获 `SIGINT/SIGTERM`，退出前结束当前会话、写入统计、释放锁。
- **通知失败阈限**：连续失败达到 `notification.failure_threshold`（默认 3 次）才弹通知，
  并有 `cooldown` 冷却，避免通知轰炸。

### 5. 唤醒 / 网络变化监听

两条腿走路，二者互补：

**① Windows 电源广播（精确、即时）**

创建隐藏的**顶层窗口**并跑消息循环，接收系统广播的 `WM_POWERBROADCAST`：

```python
WM_POWERBROADCAST      = 0x0218
PBT_APMSUSPEND         = 0x0004   # 即将休眠
PBT_APMRESUMESUSPEND   = 0x0007   # 已唤醒
PBT_APMRESUMEAUTOMATIC = 0x0012   # 自动唤醒（最常见）
```

要点：
- 必须是**顶层窗口**，不能用 `HWND_MESSAGE` 消息窗口 —— 系统广播只发给顶层窗口；
- `WNDPROC` 回调对象必须被 Python 侧持有引用，否则会被 GC 回收导致崩溃；
- 不需要管理员权限（`WM_POWERBROADCAST` 会自动广播给所有顶层窗口），
  失败时静默降级为方案 ②。

**② 时钟差值启发式（跨平台兜底）**

```python
wall_delta = time.time()      - last_wall   # 休眠期间会继续走
mono_delta = time.monotonic() - last_mono   # 休眠期间通常不走
if wall_delta - mono_delta > threshold:     # 差值即"昏迷时间"
    → 判定发生过休眠；唤醒
elif mono_delta > 预期周期 × 4:              # 进程被整体冻结（容器/虚拟机场景）
    → 同样判定为挂起后恢复
```

触发唤醒后：等待 `wake_grace`（默认 3s）让网卡与 DHCP 就绪，然后进入
`wake_fast_probes`（默认 12 次、约每 2 秒一次）的快速探测模式，尽快抢在用户打开浏览器之前恢复网络。

**网络变化**：不做重的路由表订阅（跨平台 API 差异大、权限要求高），
而是用上面的分层短周期轮询覆盖 —— `LINK_DOWN/NO_IP` 时 5 秒一次、待认证时 8 秒一次，
实际延迟已经远小于用户感知阈值，且几乎不耗资源（见下节）。

### 6. 如何最小化资源占用

| 手段 | 效果 |
| --- | --- |
| **自适应周期** | 一切正常时 30s 才探测一次；只有异常时才切到 5~8s 快轮询 |
| **HTTP 而非轮询系统 API** | 一次探测不到 1KB 流量、CPU 占用接近 0，比读路由表/网卡计数更便宜 |
| **首个目标通过即返回** | 正常时一次巡检通常只有 **1 个** HTTP 请求（`return` 提前短路） |
| **`session` 连接复用** | 复用 `requests.Session` 的 TCP 连接池，避免每次重新握手 |
| **正则只扫前 200KB** | 指纹识别只对页面头部做正则，超大页面也不卡 |
| **日志分级** | 文件保留 DEBUG，控制台只显示 INFO；第三方库（urllib3）强制 WARNING 降噪；日志按 2MB × 5 滚动 |
| **统计写盘节流 + 原子替换** | 最短 5 秒间隔才真正落盘，其余时间只在内存中累计 |
| **纯标准库做通知** | Windows 用 PowerShell 托盘气泡、macOS 用 `osascript`、Linux 用 `notify-send`，不引入额外常驻依赖 |
| **休眠期间零活动** | 收到休眠广播后不再探测，唤醒才恢复；配合 Windows 的 `pythonw.exe` 无控制台窗口 |

实测常驻内存约 15~25 MB，空闲 CPU 接近 0%。

---

## 开机自启

| 平台 | 方式 | 说明 |
| --- | --- | --- |
| Windows | `--method registry`（默认） | 写入 `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`，无需管理员权限 |
| Windows | `--method startup` | 在"启动"文件夹生成 `.vbs`，以隐藏窗口方式拉起 |
| Windows | `--method task` | 计划任务：登录时启动 + **系统从睡眠恢复时触发**（第二个任务可能需管理员权限） |
| Linux | `--method systemd` | 用户级 systemd 服务（`~/.config/systemd/user/`），`Restart=always` 自动拉起 |
| macOS | `--method launchd` | `~/Library/LaunchAgents/com.campus.autoportal.plist`，`KeepAlive` |

```bat
python auto_portal_auth.py install --method task --start-now   :: Windows 推荐与唤醒联动
python auto_portal_auth.py uninstall                           :: 卸载
```

Linux 想让服务在**未登录**时也运行：`sudo loginctl enable-linger $USER`。

---

## 故障排查

| 现象 | 排查方向 |
| --- | --- |
| 双击 `install.bat` 后不停报 `'ython' 不是内部或外部命令` | 说明 `install.bat` 被改成了纯 LF 换行，或里面加了中文/`chcp`。cmd.exe 读取 .bat 必须是 CRLF；切换代码页后它会丢字符。本仓库的 `install.bat` 保持"纯 ASCII + CRLF"即可，中文提示在 `install.py` 里。修复换行：`(Get-Content install.bat -Raw) -replace "\r?\n","\r\n" \| Set-Content install.bat -Encoding ASCII` |
| 提示 `缺少依赖: requests, PyYAML` | 首次安装直接跑 `python install.py`（它会给**当前解释器**装依赖）。机器上常有多个 Python（如商店版/托管版 3.13、`py -3` 指向的 3.14），用 `py -0p` 列出全部解释器，再用装了依赖的那个绝对路径运行，例如 `"C:\Users\...\Python312\python.exe" auto_portal_auth.py status`。错误信息里现在会直接打印解释器路径和对应的 pip 命令，复制即可。只有 `driver` / `install-extension` 两个纯本地命令不需要 PyYAML |
| 一直显示 `UNKNOWN`，日志里是 `NameResolutionError` | 校园网 DNS 未下发或需认证。看 `data/state.json` 里的 `probes` 明细；必要时在 `config.yaml` 里换探测目标为学校内网页面 |
| 显示需要认证但 `portal_url` 为空 | 认证服务器返回的是非 HTTP 响应（如 ICMP 重定向）或页面为空白。把 `detect.probe_portal_page` 保持 true，并检查 `portal_max_hops` |
| 判定为"正常"但其实打不开网页 | 你的探测目标被劫持成了"看起来正常"的页面。加一个 `expect_contains` 更严格的目标，或加 HTTPS 目标 |
| 自动登录总是失败 | 页面依赖 JS 加密（如深澜的 `SHA1` 混淆）或需要验证码。此时把 `auto_login.enabled` 关掉，改用 `open_browser`，或写自定义脚本挂到 `auth.trigger_commands` |
| 认证页弹出了，但"连接"按钮还要人手点 | 这是本版本新增功能的靶心：确认 `browser_automation.enabled: true` 且 selenium 已安装。先用 `python auto_portal_auth.py autoclick --explain` 看是否能识别到按钮；识别不到就按[识别不到按钮怎么办](#识别不到按钮怎么办)补关键词 |
| 锐捷 ePortal：按钮没有文字（`<a id="loginLink">` 里只有空 div） | 这种按钮的文字是背景图，早期版本按文本打分会识别不到。现在按 `id=loginLink` / `onclick=doauthen()` / `SLoginBtn` 识别，`--explain` 里应看到 `score >= 15`。同理，`连接网络` 这种标题文字（div/span）会被判为"非按钮"扣分，不会乱点 |
| 点了登录但页面提示"请填写用户名/密码" | 页面需要真的填账号密码。确认 `auth.auto_login.enabled: true` 且 `username` / `password` 已填，`browser_automation.fill_credentials` 保持 true（默认）。日志里会打印"已填写登录账号「xxx」和密码（密码框可见=True）" |
| 改了代码/升级后仍旧要手动点 | 守护进程是常驻的，**启动时**就把代码读进内存了。改完代码必须重启：任务管理器结束 `pythonw.exe`，再重新运行（或注销重登，让自启项拉起新进程） |
| 日志提示"未安装 selenium" | `python -m pip install selenium`，然后 `python auto_portal_auth.py driver --download` 预下载驱动（第一次需要联网） |
| `driver --download` 失败 / 提示 Selenium Manager | 首次必须能上外网。可以在能上网的环境执行一次，驱动会缓存到 `~/.cache/selenium`；或改用扩展方案 C |
| 自动点击"已点击"但没恢复联网 | 看 `data/autoclick/fail-*.png`。常见原因：还需要验证码、点了"取消"、或认证被后端拒绝。把目标按钮文本加进 `button_texts` 或加 `extra_button_selectors` |
| 无头模式点了没反应 | 用 `headless: false`（或 `autoclick --headed`）。部分 Portal 的 JS 会检测无头浏览器 |
| 装了扩展但认证页没自动点 | 认证页需刷新一次（安装扩展前已打开的页面不会注入）。点扩展图标选"立即在本页执行一次"看识别结果；内网域名可在弹窗点"本网站总是启用" |
| 浏览器没有自动弹出 | 检查 `auth.open_browser`；冷却是 90s，同一认证页 90s 内不会重复打开（日志级别 `--log-level DEBUG` 能看到原因） |
| 唤醒后很久才恢复 | 确认 `wake_fast_probes` > 0；Windows 上可改用 `--method task` 注册唤醒计划任务双保险 |
| 想确认空闲超时到底多久 | 跑几天后执行 `python auto_portal_auth.py analyze`，看 `median` 与 `suggested_keepalive` |

日志文件：`logs/auto_portal_auth.log`（滚动，保留 5 份）；实时观察用 `-v` 前台运行。

---

## 安全提示

- `config.yaml` 里的 `auto_login.password` 是**明文**。请限制文件权限：

  ```bash
  chmod 600 config.yaml            # Linux / macOS
  ```
  ```powershell
  icacls config.yaml /inheritance:r /grant:r "$env:USERNAME:(R,W)"
  ```

- 程序只在本机发起请求，不上传任何数据；统计文件 `data/stats.json` 只包含时间戳、时长与厂商名，
  **不包含**账号密码。日志同样不会打印密码（只打印字段个数）。
- 打开浏览器触发认证时会使用系统默认浏览器，认证页可能是 `http://` 明文 —— 这是校园网 Portal
  的常态，与程序本身无关。

---

## 项目结构

```
auto_portal_auth.py      主程序（检测 / 认证 / 监听 / 统计 / 自启安装 / 命令行）
portal_autoclick.py      Selenium 自动点击引擎（方案 A：勾选条款 + 点击连接）
config.yaml             配置文件（全部可选项都有注释）
requirements.txt        Python 依赖（requests / PyYAML / psutil / selenium）
install.py              交互式安装器（中文提示、UTF-8，跨平台）
install.bat             Windows 启动器（刻意保持"纯 ASCII + CRLF"，只负责调 install.py）
install.sh              Linux / macOS 安装脚本
README.md               本文件
extension/              浏览器扩展（方案 C：不依赖 Python，页面一开就点）
tests/                  自动化测试（fake_portal_server.py 假认证页 + test_autoclick.py）
logs/                   运行日志（自动创建，滚动保留）
data/                   状态快照 auto_portal_auth.lock(锁) / state.json / stats.json（自动创建）
  autoclick/            自动点击失败时的截图与 HTML（自动创建）
  browser_profile/      自动点击专用的浏览器配置（自动创建）
```

依赖：Python 3.8+、`requests`、`PyYAML`、`psutil`（可选但强烈建议）、`selenium`（自动点击用，缺失时自动降级）。
