# AutoPortalAuth — 校园网 Portal 自动认证守护程序

> 解决"睡眠唤醒 / 开机后必须打开浏览器才能上网"的问题：主动探测 → 发现被 Portal 拦截 → 自动触发认证 → 恢复网络，并统计空闲超时规律做**心跳保活**，把掉线消灭在发生之前。

---

## 目录

- [它是怎么工作的](#它是怎么工作的)
- [快速开始](#快速开始)
- [命令一览](#命令一览)
- [配置文件重点项](#配置文件重点项)
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
3. 对页面做厂商指纹识别，然后按顺序尝试：**静默自动登录** → **自定义触发命令** → **HTTP GET 戳认证页** → **打开默认浏览器**；
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

notification:
  enabled: true           # 认证成功/失败时的系统通知
```

> **推荐做法**：先只开 `open_browser`（默认），跑几天让程序统计出校园网的空闲超时时间；
> 执行 `python auto_portal_auth.py analyze` 看到建议值后，把 `auth.keepalive.interval`
> 设为略小于超时时间的值，掉线率会显著下降。若你的 Portal 允许脚本登录（多数锐捷/深澜的
> `/eportal`、`/srun_portal` 接口都可以），再填账号密码开启 `auto_login`。

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
| 提示 `缺少依赖: requests, PyYAML` | `install.bat` 挑中的 Python 解释器没装依赖。直接跑 `python install.py`（它会给该解释器装依赖），或手动 `python -m pip install -r requirements.txt`。想固定解释器：`python install.py` 里会用 `sys.executable`，之后自启也用同一个 |
| 一直显示 `UNKNOWN`，日志里是 `NameResolutionError` | 校园网 DNS 未下发或需认证。看 `data/state.json` 里的 `probes` 明细；必要时在 `config.yaml` 里换探测目标为学校内网页面 |
| 显示需要认证但 `portal_url` 为空 | 认证服务器返回的是非 HTTP 响应（如 ICMP 重定向）或页面为空白。把 `detect.probe_portal_page` 保持 true，并检查 `portal_max_hops` |
| 判定为"正常"但其实打不开网页 | 你的探测目标被劫持成了"看起来正常"的页面。加一个 `expect_contains` 更严格的目标，或加 HTTPS 目标 |
| 自动登录总是失败 | 页面依赖 JS 加密（如深澜的 `SHA1` 混淆）或需要验证码。此时把 `auto_login.enabled` 关掉，改用 `open_browser`，或写自定义脚本挂到 `auth.trigger_commands` |
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
config.yaml             配置文件（全部可选项都有注释）
requirements.txt        Python 依赖（requests / PyYAML / psutil）
install.py              交互式安装器（中文提示、UTF-8，跨平台）
install.bat             Windows 启动器（刻意保持"纯 ASCII + CRLF"，只负责调 install.py）
install.sh              Linux / macOS 安装脚本
README.md               本文件
logs/                   运行日志（自动创建，滚动保留）
data/                   状态快照 auto_portal_auth.lock(锁) / state.json / stats.json（自动创建）
```

依赖：Python 3.8+、`requests`、`PyYAML`、`psutil`（可选但强烈建议）。
