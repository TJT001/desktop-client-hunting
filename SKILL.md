---
name: desktop-client-hunting
description: |
  Use when 做桌面客户端漏洞挖掘（Electron / CEF / CefSharp / WebView2 / Qt WebEngine /
  NW.js / Tauri / WPF / WinForms / WinUI3 / 自研内嵌浏览器），或判断“网页、聊天消息、二维码、自定义协议
  → 客户端”这条投递链成不成立。触发词：桌面客户端、客户端漏洞挖掘、客户端 RCE、
  内嵌浏览器、自定义协议、deep link、URL scheme、JS 桥、native bridge、IPC、
  本地服务、自动更新、插件、DevTools、Electron、CEF、WebView2、Tauri；
  也包括“这个客户端能不能被打”“客户端里执行 JS 算不算漏洞”“本地提权/中间人/
  调试端口值不值得继续”。只对已授权目标、私有测试环境；不破坏数据、不碰真资损。
---

# 桌面客户端漏洞挖掘（通用）

> 范围：本技能只管**客户端边界**与**投递链**；Web 侧漏洞类型、报告模板、CORS /
> 登出 / 资损这类红线见 `references/report-format.md`，不在本文件重复。

## 0. 一句话

只认 **可达 source → 已确认 delivery → 客户端 sink**。  
**引擎不是漏洞，边界才是；sink 不是漏洞，投递才是。**

- 能开任意网页的内嵌窗口、能调本地文件/剪贴板 API、能跑引擎 1day —— 都是 **sink**；
- 本地 DevTools、`--no-sandbox`、本地配置/文件、本机恶意软件 —— 都是 **本地能力**，不是外部漏洞；
- 聊天链接/菜单链接实际走系统浏览器 —— 该路径判负，别拿页面里能执行 JS 硬解释；
- 只有“普通互联网攻击者能产生”的输入进了客户端，才按客户端漏洞定级。
- **只读目标**：不修改目标项目的任何文件内容；需要改动时用副本/快照，测完恢复。
- **按实际加载定攻击面**：攻击面梳理先看主进程（及各子进程）**真实加载的模块**（OpenArk `ps_module_list` 等），不是安装目录里有哪些 DLL。没加载的 DLL 不可达，挖了浪费；只有确认会被动态加载（更新、插件、延迟加载）才纳入。

## 1. 五条硬规则

1. **外部可达优先**  
   攻击者必须能通过互联网产生这个输入：别人发的消息/公告/资料、公开网页、二维码、
   可被外部影响的运营/广告配置、客户端会跟随的跳转。  
   本地访问、同 LAN、MITM、调试端口、本地文件/配置、物理接触，**不计入**外部漏洞。  
   本地发现默认不报；**例外是跨权限边界的提权/沙箱逃逸**（见 §9.1）。

2. **sink ≠ source**  
   自定义协议、`shell.openExternal`、桥方法、渲染进程 RCE 都只是 sink。  
   先回答：**谁把 URL / HTML / JS / 参数喂进来？** 找不到 source，就停在“sink 已验证”。

3. **先证投递，再谈上限**  
   投递未确认：只写“潜在/未确认”，不写“账号接管/RCE”。  
   投递确认后，再按 `页面 JS → 桥 → 凭证/文件 → 命令执行 → 持久化` 逐级评估。

4. **代码级确认**  
   功能、协议、桥、解析器都要逆向/反编译/反汇编理解真实逻辑；界面猜测不算。  
   结论落到函数/行号/调用链，或动态断点/回显；代码层或实际验证过才写。

5. **导出 ≠ 可达**  
   二进制/原生 API 的漏洞先确认**被程序实际使用**：有真实调用方（xrefs / 调用链 / 导入表），或动态断点确认命中；只存在于导出表、没有调用路径的函数不测、不报。  
   导出表只用来“找候选”，绝不能直接对导出函数构造调用去测。

## 2. 判定闸门（任何一关为否：降级或停）

| 闸门 | 问题 | 不通过时 |
|---|---|---|
| **G0 输入可达** | 普通互联网攻击者能否产生这个输入？ | 本地/同 LAN/MITM/物理/调试端口 → 丢弃（跨权限边界的提权走 §9.1） |
| **G1 引擎确认** | 输入进的是客户端内嵌引擎/原生解析器，不是系统浏览器？ | 只写“sink/未确认”，不写外部链 |
| **G2 能力确认** | 进入后能执行 JS、调桥、读文件、拉起协议，或触发解析器内存错误/反序列化？ | 继续找 sink，不写影响 |
| **G3 影响** | 凭证/账号/文件/命令执行/持久化？ | 没有 G1 不写 G3 |

## 3. 客户端类型速判

| 类型 | 快速识别 | 常见桥 / 入口 | 先看什么 |
|---|---|---|---|
| **Electron** | `resources/app.asar`、`electron*.dll`；子进程带 `--type=renderer`；UA 常含 `Electron/x` | `window.require`、`process`、preload 暴露对象、`ipcRenderer`、`<webview>` 标签 | `nodeIntegration`、`contextIsolation`、`sandbox`、`webviewTag`、`shell.openExternal` |
| **CEF / CefSharp** | `libcef.dll`、`CefSharp*.dll`、`*Subprocess.exe`；UA 常带产品 token | `CefMessageRouter`（`window.cefQuery`）、注册的 JS 对象、`OnProtocolExecution` | 自定义 scheme、消息路由、`CefV8Handler` 拼接、`allow_os_execution` |
| **WebView2** | `msedgewebview2.exe`、`WebView2Loader.dll`；UA 含 `Edg/` | `chrome.webview.postMessage`、`hostObjects` | `AddHostObjectToScript`、`WebMessageReceived` 是否校验来源 |
| **Qt WebEngine** | `Qt*WebEngineCore.dll`、`QtWebEngineProcess.exe` | `QWebChannel`、`qt.webChannelTransport` | 暴露的 QObject、`runJavaScript` 拼接 |
| **NW.js** | 进程加载 `nw.dll`、`package.json` 的 `node-main` | Node 全量 + DOM | `node-remote`、`--mixed-context` |
| **Tauri** | Win 走 WebView2、mac 走 WKWebView；Rust 主程序 | `__TAURI__.invoke` / `__TAURI_INTERNALS__.invoke` | `tauri.conf.json` 的 allowlist/capabilities、命令参数校验、asset/shell/fs scope |
| **自研 / 内嵌** | 独立渲染子进程、私有 scheme、DevTools 被裁 | 自研 `jsbridge://`、注入对象、命令行 | 找注入点与协议分发，别假设“和 Chromium 一样” |
| **WPF / WinForms** | .NET 程序集、`PresentationFramework`/`System.Windows.Forms`；常内嵌 WebView2/CEF | 本地 HTTP/WS、命名管道、JS bridge、文件解析 | 反编译 .NET、看 IPC/端口/文件解析 |
| **WinUI3 / Windows App SDK** | `Microsoft.WindowsAppRuntime`、WebView2 | WebView2 消息、本地服务、打包/更新 | 同 WebView2 + 应用包边界 |

> 识别线索可以来自安装目录，但**定攻击面以 §8 第 1 步的进程实际加载模块为准**。

细节与各引擎危险配置见 `references/client-surfaces.md`；CEF 专项审计见 `references/cef-trust-boundaries.md`，Electron 专项见 `references/electron-trust-boundaries.md`。黑盒攻击面清单见 `references/blackbox-surfaces.md`，案例见 `references/case-library.md`。

## 4. 挖什么（Go）

| 输入面 | 谁能产生 | 判据 | 常见坑 |
|---|---|---|---|
| **自定义协议 / deep link** | 任意网页、别的 App、聊天软件 | 点一下或扫码就能到；参数含 `url`/`open`/`openUrl`/`webview`/`command` | 只认自家域；只弹“打开应用”；参数被白名单过滤 |
| **用户间内容** | 另一个普通用户 | 消息/公告/资料/分享卡片里的链接或富文本进了内嵌浏览器 | 实际走系统浏览器；需对方点两次；需频道主权限 |
| **运营 / 广告配置** | 广告主、频道主、外部配置 | URL/HTML 字段能进内嵌窗口或模板 | 只有官方运营能配 → 降级为“运营/服务端” |
| **二维码** | 任意人摆一个码 | 客户端扫码后直接打开 URL/scheme | 扫码器二次确认；只允许自家域 |
| **网页跳转** | 任意站点 | 客户端跟随 302 / `target=_blank` / `window.open` 进内嵌浏览器 | 被 `forbidPopup` 拦；转到系统浏览器 |
| **JS 桥返回值** | 原生侧可控数据 | 返回字符串拼进 `eval` / `runJavaScript` 未转义 | 返回值本身是否可被互联网影响 |
| **本地服务 / IPC** | 本机其他进程、网页 | 端口/管道可达且无鉴权 | 只有本机可达 → 本地能力，不是外部漏洞 |
| **自动更新 / 插件** | 更新服务器、插件市场 | 未签名 / 可降级 / 可劫持 | 需要供应链或网络位置 → 通常不算普通外部 |
| **文件 / 协议解析** | 任意发文件的人 | 打开即解析；解析器有内存或命令问题 | 只崩不算；方法见 `references/memory-safety.md` |
| **反序列化 / 类型化数据** | 发文件、发消息、插件、导入/备份、渲染进程 | 外部数据进了 `BinaryFormatter`/`ObjectInputStream`/`pickle`/`unserialize`/`TypeNameHandling` 等 | 先找 source；类型可控才谈 gadget；见 `references/deserialization.md` |
| **鉴权 / 白名单** | 客户端请求、预览、跳转、特权域 | token/cookie/ticket 被带到攻击者 URL；`trusted.com@evil.com` 绕过 | 只影响自己账号不算；要跨用户/跨域 |
| **内嵌浏览器 / file 域** | 任意页面、本地 HTML、下载目录 | `file://` 可读/跨域/删文件；特权域 XSS | 需要本地用户名/路径时降级；先证页面进客户端 |

## 5. 不挖什么（Stop）

| 不挖 | 原因 |
|---|---|
| 本地 DevTools / `--remote-debugging-port` / `--inspect` | 需要本机访问；不按外部报。例外：跨权限边界（低权限→高权限/沙箱逃逸）按本地提权报 |
| MITM / 证书忽略 / 更新劫持 | 网络位置类；不是“用户点链接”外部可达 |
| 本地文件/配置注入 | 除非能由互联网下发；或跨权限边界 |
| 只有本地能力的桥（读写文件、剪贴板、机器码） | 没有 source 就只是本地能力；跨权限边界才按提权 |
| 同用户本地代码执行 / 本地读写 / 本地 DoS | 没有跨权限边界，不报 |
| 单独的内嵌窗口 / 任意 URL 打开 | sink only；先找 source |
| 只在导出表里、无调用方的 native API | 程序不用它就不可达；先证被调用（xrefs/断点），export-only 不测 |
| 只崩不执行（无效 id、畸形参数） | DoS 不算；不要反复 fuzz |
| self-XSS / 需要受害者自己粘贴 | 不成立 |
| CORS | 永久不挖 |
| 登出/注销、破坏性写、真资损 | 不挖 |
| 纯系统浏览器路径 | 不在客户端边界内 |
| 官方运营/服务端鉴权才能配置的入口 | 降级为“服务端/运营配置”，不按普通外部投递 |
| 公开 1day 直接套 | 先确认引擎版本/位数/沙箱/投递；不确认就只是“潜在” |

## 6. 一条投递链怎么证

顺序不能反：

1. **列 source**：按 `references/blackbox-surfaces.md` 和 `references/client-surfaces.md` §2 把目标客户端的输入面抄成表，每条标“谁能产生”和状态。
2. **证明进的是客户端**：UA 金丝雀 + 进程/命令行 + 内嵌窗口 target；系统浏览器命中直接判负。（G1）
3. **证明进去能做什么**：页面里探桥/权限/Node/QWebChannel；调一个只读方法。（G2）
4. **最小影响**：读自己的 uid、写自己的临时文件、本机弹计算器；不做破坏性动作。（G3）
5. **补真实互联网路径**：换另一个测试账号发消息/公告/二维码，复现同一跳转；只有你能在终端里 `start` 不算。
6. **落表**：每条 `Go / Stop / 待验证`，写清证据文件；同步到 `notes/00-surface.md` 和 `notes/10-progress.md`（见 §12）。

证据最少三样：**UA 日志、进程命令行/端口、桥返回值或页面 marker**。

## 7. 影响阶梯

| 级别 | 证据 | 报告口径 |
|---|---|---|
| **L1 页面 JS** | marker 执行，无桥 | 客户端内 XSS；再看能否读凭证/跨域 |
| **L2 桥调用** | `getUid` / 版本 / 票据长度 | 客户端桥暴露；看凭证 |
| **L3 凭证 / 账号** | 拿自己的票据/登录态 | 账号接管链；票据只写长度 |
| **L4 文件 / 命令** | 写自己的临时文件、本机弹计算器 | RCE；本地同用户不按提权报 |
| **L5 持久化** | 不默认验证 | 启动项/更新/服务；只写可达路径 |

## 8. 动态验证

细节见 `references/dynamic-verification.md`；Windows 工具命令见 `references/windows-toolchain.md`。这里只留顺序：

1. **认进程、认模块，不认文件夹**：先用 OpenArk（`ps_list` / `ps_module_list` / `ps_tree`）或 Tasklist / Process Explorer 枚举主进程**实际加载的模块清单**，以加载情况为准定攻击面（解析器、网络栈、序列化库都在里面）；安装目录里躺着但没被加载的 DLL 一律不挖，除非动态确认了加载路径。子进程（renderer/gpu/utility）单独列模块，分别认边界。
2. 开调试（**本地研究用，不作为漏洞**）：Chromium `--remote-debugging-port`、Electron `--inspect`、WebView2 环境变量
3. UA 金丝雀：区分内嵌引擎 vs 系统浏览器
4. 桥探测：`require` / `process` / `chrome.webview` / `QWebChannel` / `__TAURI__` / CEF 注入对象
5. 协议与投递：从网页/聊天/二维码触发，不从终端 `start`
6. 动态调试：x64dbg（用户态）/ WinDbg（崩溃、堆、TTD、内核）
7. 最小影响验证
8. 恢复与取证

## 9. 报告口径

- 标题写 **source → delivery → sink**，不要只写 sink。
- 三列：**互联网输入** / **投递是否确认** / **客户端能力**。
- 未确认投递：写“潜在/未确认”，不写 RCE/账号接管。
- 引擎 1day、调试端口、MITM：放“附注/不纳入外部评级”；本地提权按 §9.1 单独报。
- 敏感值脱敏：票据只写长度；不复述 cookie/token/机器码。
- 定级前问一句：**普通互联网攻击者能不能触发？** 不能就不按外部漏洞报。
- 正式报告格式、攻击面表、CVSS 表、exp 附件见 `references/report-format.md`。

### 9.1 本地漏洞口径

默认不按外部漏洞报；只有**跨权限边界**才按本地提权/沙箱逃逸上报。

| 本地发现 | 是否上报 |
|---|---|
| 同用户本地代码执行 / 本地读写 / 本地 DoS | 不报：没有跨边界，攻击者已拥有同等权限 |
| 标准用户 → 管理员 / SYSTEM / root | 报：本地提权 |
| 低完整性 / AppContainer / 渲染进程沙箱 → 中/高完整性或宿主 | 报：沙箱逃逸/提权 |
| 渲染进程 → 主进程/浏览器进程 | 报：作为链的一环；渲染进程若可由互联网输入控制，写完整链 |
| UAC 绕过 | 看项目范围；不少 SRC 不收，先查规则 |
| 物理接触 / 本机恶意软件 / 同 LAN | 不报 |

报告必须写清：**从什么权限上下文 → 到什么权限上下文**，以及证据（`whoami /priv`、完整性级别、token、进程属主、沙箱状态）。

## 10. 反空转

- 没有互联网 source：停，不要继续测本地 sink。
- 本地 sink 没有跨权限边界：停，不要按外部或提权写。
- 命中系统浏览器：该路径判负，换下一个入口。
- 只有官方运营/服务端能配：降级，不算普通外部投递。
- XSS/注入已确认但参数没有互联网控制：只写“客户端内执行”，不写外部链。
- 只崩不执行：记录后停，不要反复 fuzz。
- 只有 Win+R/终端能触发协议：没有外部投递，判负。
- Bridge 只在特权域可用：没有特权域 XSS/绕过，判负。
- URL/路径在更早的地方已被过滤：到不了 sink，判负。
- 预览/跳转实际走系统浏览器：不在客户端边界内，判负。
- 一轮结束更新输入面表，每条标 `Go / Stop / 待验证`。

## 11. 快速清单

- [ ] 输入是互联网可达的吗？
- [ ] 真的进了客户端内嵌引擎（UA/进程/target）吗？
- [ ] 页面有桥 / 能执行 JS / 能拉协议吗？
- [ ] 内存类：外部输入能到解析器吗？崩溃 triage 成 primitive 了吗？
- [ ] 反序列化：外部数据到了哪个反序列化器？类型可控吗？
- [ ] 凭证/账号/文件/命令执行哪一级？
- [ ] 是 sink 还是 source？
- [ ] 二进制 API：确认被程序调用过吗（xrefs/断点），还是只对着导出表硬测？
- [ ] 有没有把本地/MITM/调试端口当外部漏洞？
- [ ] 本地发现是否跨了权限边界（提权/沙箱逃逸）？
- [ ] 是否逆向/反编译/动态验证过真实调用链？
- [ ] Windows 工具链（OpenArk/IDA/rabin2/asar/frida/cdb/procdump/Ghidra）是否用上？
- [ ] 测试环境是否私有？测完是否恢复？
- [ ] 报告是否标了“已确认/未确认”？

## 12. 项目缓存

在当前工作目录建 `notes/`（或 `<目标>-client-notes/`），至少四份：

| 文件 | 内容 |
|---|---|
| `notes/00-surface.md` | 攻击面表（§3/§4 + `blackbox-surfaces.md`），每条带状态 |
| `notes/10-progress.md` | 每个入口的 Go/Stop/待验证、证据路径、测试时间 |
| `notes/20-findings.md` | 候选漏洞、验证状态、报告草稿 |
| `notes/30-evidence/` | 日志、截图、dump、exp、回环服务日志 |

上下文压缩/换会话后先读这四份，避免重复测试和遗忘证据。

## 13. 本技能文件

| 文件 | 用途 |
|---|---|
| `references/blackbox-surfaces.md` | 黑盒攻击面：框架、协议、端口、功能、JS bridge、文件类型、鉴权、逆向要求 |
| `references/case-library.md` | 客户端漏洞案例库（协议/端口/桥/解析/社交）+ 判负案例 + 无害 PoC |
| `references/windows-toolchain.md` | OpenArk/IDA 用法，PowerShell/rabin2/asar/curl/frida/cdb/procdump/Ghidra 命令与组合流程 |
| `references/report-format.md` | 项目缓存、攻击面表、CVSS 详情表、exp 附件、交付检查 |
| `references/client-surfaces.md` | 引擎识别、外部输入面、sink 分类、各引擎危险 API、协议解析、本地服务、更新/插件 |
| `references/cef-trust-boundaries.md` | CEF 四层信任边界：引擎 / 框架 IPC / 绑定层 / 配置与调试；含按 Chromium 基线回溯全部 Chrome CVE 的方法 |
| `references/electron-trust-boundaries.md` | Electron 四层信任边界：引擎 / IPC / preload 与 contextBridge / fuses 与调试；含已核对 CVE 示例 |
| `references/memory-safety.md` | 外部输入 → 原生解析器/进程的内存类漏洞：输入面、到达性、bug 类型、版本回溯、fuzzing、崩溃 triage、报告 |
| `references/deserialization.md` | 反序列化攻击面：输入面、各运行时危险入口、格式识别、D0–D3 闸门、gadget 验证、报告 |
| `references/dynamic-verification.md` | 认进程、开调试、UA 金丝雀、桥探测、协议与投递测试、清理取证 |

