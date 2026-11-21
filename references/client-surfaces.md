# 客户端攻击面速查（通用）

> 用法：先按 §1 认引擎，再按 §2 列 source，按 §3 认 sink，最后回到 `SKILL.md` 的 G0–G3。  
> 本文件只给判断依据，不给“某客户端一定如何”的结论；换目标就重建自己的表。  
> 黑盒攻击面清单见 `blackbox-surfaces.md`；案例见 `case-library.md`；Windows 工具链见 `windows-toolchain.md`；报告格式见 `report-format.md`。

## 1. 认引擎

三件套：**安装目录 → 进程/模块 → UA 与页面能力**。三者对上再下结论。

| 引擎 | 安装目录 / 模块线索 | 进程线索 | UA 线索 | 调试入口 |
|---|---|---|---|---|
| Electron | `resources/app.asar`、`electron*.dll`、`package.json` | 主进程 + 多个 `--type=renderer/gpu` 子进程 | 默认追加 `Electron/x.y.z`（可能被覆盖） | `--remote-debugging-port=9222`；主进程 `--inspect=5858` |
| CEF / CefSharp | `libcef.dll`、`CefSharp*.dll`、`CefSharp.BrowserSubprocess.exe` | 宿主 exe + 独立 subprocess exe | 常见产品 token + Chromium 版本，无 `Edg/` | 命令行 `--remote-debugging-port`；或产品配置里的 `remote_debugging_port` |
| WebView2 | `WebView2Loader.dll`、`msedgewebview2.exe` | 宿主 exe + `msedgewebview2.exe` 多进程 | 含 `Edg/<version>` | 启动前设 `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--remote-debugging-port=9222` |
| Qt WebEngine | `Qt*WebEngineCore.dll`、`QtWebEngineProcess.exe` | 宿主 exe + `QtWebEngineProcess.exe` | 常为裸 Chrome UA 或产品自定义 | Chromium 系参数；产品可能关闭 |
| NW.js | `nw.dll`、`package.json`（`node-main`）、`nw.pak` | 宿主 exe + renderer 子进程 | 常含 `nw.js` 或产品名 | Chromium 参数；`--mixed-context` |
| Tauri | 无 Chromium 自带（Win 用系统 WebView2，mac 用 WKWebView） | 宿主 exe + `msedgewebview2.exe` / `com.apple.WebKit.*` | Win 含 `Edg/`；mac 含 `Safari/` | Win 同 WebView2；mac 用 Safari 远程检查 |
| 自研 / 内嵌 | 私有 dll、独立渲染进程、私有 scheme | 子进程命名不固定 | 不固定 | 找产品自己的 devtools 开关 |

补充识别：

- 安装目录里找 `resources/`、`locales/`、`*.pak`、`icudtl.dat`、`snapshot_blob.bin` → Chromium 系。
- 进程命令行里找 `--user-data-dir`、`--no-sandbox`、`--disable-web-security`、`--ignore-certificate-errors`、`--remote-debugging-port`。
- 模块里找 `node.dll` / `nw.dll` → NW.js 或 Node 嵌入；`V8` 版本随引擎版本走。**模块以进程实际加载为准**（OpenArk `ps_module_list` / `Get-Process … | % Modules`）：识别引擎时安装目录文件只当线索，定攻击面时未加载的 DLL 不算。
- 页面里 `navigator.userAgent`、`navigator.userAgentData`、`process.versions`（Electron/Node）、`chrome.runtime`。

## 2. 外部输入面（source）

| 输入面 | 典型载体 | 外部可控性 | 验证要点 |
|---|---|---|---|
| 自定义协议 / deep link | `scheme://...`、`<a href>`、聊天消息、二维码、系统分享 | 任意网页 / 任意 App / 任意发消息的人 | 点一下是否直达；是否弹确认；参数怎么解析 |
| 用户间内容 | 私聊、群消息、公告、资料卡、签名、分享卡片、名片 | 另一个普通用户 | 链接/富文本是否进内嵌引擎；是否需要额外点击 |
| 运营 / 广告配置 | 弹窗、banner、活动页、推送落地页、频道模板 | 广告主 / 频道主 / 运营后台 | 哪些字段写 URL/HTML；普通用户能否影响 |
| 网页跳转 | 302、`target=_blank`、`window.open`、`location` | 任意站点 | 客户端是否跟随；是否被弹窗策略拦 |
| 二维码 | 线下/图片/网页里的码 | 任意人 | 扫码后是否直接打开；是否二次确认 |
| 文件 / 协议解析 | 发文件、拖拽、剪贴板、文件关联 | 任意发文件的人 | 打开即解析；是否有命令注入/路径穿越/内存问题 |
| 自动更新 / 插件 | 更新源、插件市场、扩展包 | 更新服务器 / 插件作者 | 签名、降级、渠道配置、包内路径 |
| 本地服务 / IPC | localhost HTTP/WS、命名管道、Unix socket、COM/DBus | 本机进程；网页（DNS rebinding/CSRF） | 绑定地址、鉴权、Origin 校验 |
| 登录 / SSO 回调 | 自定义 scheme 回调、loopback 端口 | 任意网页可触发回调 | 是否校验 state/code，能否被抢注 |

判定“外部可达”只问一句：**一个只有互联网、没有本机权限的攻击者，能不能让受害者产生这个输入？**
能 → 继续 G1；不能 → 本地能力或网络位置，不进主定级。

## 3. Sink 与能力

| Sink 类型 | 能力 | 单独算漏洞吗 |
|---|---|---|
| 内嵌窗口打开任意 URL | 页面在客户端引擎里跑，可能带桥 | 不算；要有 source |
| `window.open` / 新窗口 | 新内嵌页 / 系统浏览器 | 不算；先看落到哪 |
| 页面 JS 执行 | 读 DOM、发请求、调桥 | 不算；要看能否读凭证/跨域/调桥 |
| 桥方法 | 原生能力：uid、票据、文件、剪贴板、命令 | 不算；要有 source + 方法确实可用 |
| 协议拉起 | 启动别的程序 / 传参 | 不算；参数可控才有意义 |
| 本地文件 API | 读写删、路径可控 | 不算；本地能力 |
| 引擎 1day | 渲染进程代码执行 | 不算；版本/位数/沙箱/投递都要对 |
| 更新 / 插件加载 | 落地文件、执行 | 通常需要供应链/网络位置 |

## 4. 各引擎的危险配置与 API

### Electron

- `webPreferences`：`nodeIntegration`、`contextIsolation`、`sandbox`、`webviewTag`、`webSecurity`、`allowRunningInsecureContent`、`preload`。
- `shell.openExternal(url)` / `shell.openPath(path)`：把不可信输入传进去可拉起任意 scheme / 本地程序。
- `app.setAsDefaultProtocolClient` + `open-url` / `second-instance`：协议参数解析。
- `ipcMain.on/handle`：不校验 `event.senderFrame` / 来源，渲染进程可越权调主进程能力。
- `webContents.executeJavaScript` / `loadURL`：拼接不可信字符串。
- `protocol.registerFileProtocol` / `handle`：路径穿越。
- `setWindowOpenHandler` / `will-navigate`：未限制则任意跳转。
- `<webview>` 标签：`nodeintegration`、`preload`、`src` 可控。
- 四层信任边界、fuses、IPC/contextBridge 审计与 CVE 示例见 `electron-trust-boundaries.md`。

### CEF / CefSharp

- `CefMessageRouter`：`window.cefQuery({request, onSuccess, onFailure})`，看 query 是否被拼进命令/URL。
- `CefV8Handler::Execute`：返回值拼 `eval` / `runJavaScript` 未转义。
- `OnProtocolExecution`（`allow_os_execution`）：任意页面 `scheme://` 拉起本机程序。
- `OnBeforeBrowse` / `OnBeforePopup`：是否限制 scheme/域名。
- 自定义 scheme handler：路径穿越、读任意文件。
- CefSharp：`JavascriptObjectRepository.Register` / `BindObjectAsync` 暴露的对象与方法。
- `EvaluateScriptAsync`：拼接不可信字符串。
- 四层信任边界、共享内存与已核对 CVE 速查见 `cef-trust-boundaries.md`。

### WebView2

- `AddHostObjectToScript`：`chrome.webview.hostObjects.<name>`，方法参数/返回值是否可信。
- `WebMessageReceived`：是否校验 `Source` / Origin。
- `ExecuteScriptAsync`：拼接。
- `SetVirtualHostNameToFolderMapping`：虚拟主机映射目录，注意路径。
- `NewWindowRequested` / `NavigationStarting`：是否限制外站。
- `CoreWebView2.Settings`：`AreDevToolsEnabled`、`IsWebMessageEnabled`、`AreHostObjectsAllowed`。

### Qt WebEngine

- `QWebChannel` 注册的 QObject：`channel.objects.<name>` 暴露的槽/属性。
- `runJavaScript`：拼接。
- `QWebEngineUrlSchemeHandler`：自定义 scheme 解析。
- `acceptNavigationRequest` / `createWindow`：是否限制。

### Tauri

- `invoke` 命令：参数校验、路径拼接、命令注入。
- `tauri.conf.json`：`allowlist`（v1）/ `capabilities` + permissions（v2）、`assetProtocol.scope`、`shell`/`fs` scope、CSP。
- v1 `dangerousRemoteDomainIpcAccess`：远程域可调 IPC。
- `withGlobalTauri`：页面可直接拿 `__TAURI__`。

### NW.js

- DOM 里直接 `require`：`require('child_process')` 即可执行。
- `node-remote`：允许远程页面拿 Node。
- `--mixed-context`：混合上下文。
- `node-main`：启动脚本。

### 移动端混合容器（同一套逻辑）

- Android：`addJavascriptInterface` → `window.<name>`；`shouldOverrideUrlLoading` / `intent://`；深度链接。
- iOS：`WKScriptMessageHandler` → `window.webkit.messageHandlers.<name>.postMessage`；Universal Links。
- 具体流量/反编译流程见 `dynamic-verification.md` 与 `windows-toolchain.md`。

## 5. 自定义协议解析

注册位置：

| 平台 | 位置 |
|---|---|
| Windows | `HKCU\Software\Classes\<scheme>` 或 `HKCR\<scheme>`；`URL Protocol` 值 + `shell\open\command` |
| macOS | `Info.plist` → `CFBundleURLTypes` → `CFBundleURLSchemes` |
| Linux | `.desktop` 的 `MimeType=x-scheme-handler/<scheme>;` + `xdg-mime default` |

解析坑（逐条试，别只试一种）：

- 百分号解码一次还是两次；`+` 是否当空格。
- `scheme:payload` 与 `scheme://host/path` 两种形态；有的客户端把 `:` 后全当不透明串。
- 嵌套 scheme：`scheme://x?url=scheme2://...`、`scheme:scheme2://...`。
- base64（标准/URL-safe、有无 padding）；再套一层编码。
- `@`、`\`、`%00`、`%2f`、`..`、前后空白、大小写、超长截断、`#` 后内容。
- 参数被拼进命令行：空格/引号是否导致参数注入。
- 是否只校验前缀（`scheme://trusted.com@evil.com`、`scheme://trusted.com.evil.com`）。
- 是否只允许自家域：允许列表在客户端还是服务端。

验证时从**浏览器页面、聊天消息、二维码**触发，不要只在终端 `start` —— 终端能起不代表互联网可达。

## 6. 本地服务与 IPC

- HTTP/WS 服务：看绑定 `127.0.0.1` 还是 `0.0.0.0`；有无 token；有无 Origin/Referer 校验。
- 网页打本地服务：DNS rebinding、CSRF、WebSocket 无 Origin 校验。CORS 本身不报，但**缺鉴权**要报。
- 命名管道 / Unix socket：ACL、是否校验调用者。
- COM / DBus：接口是否暴露危险方法。
- 只有本机用户可达 → **本地权限边界**，不进外部定级；除非网页/远程输入能驱动它，或能跨到更高权限（提权/沙箱逃逸）。

## 7. 自动更新 / 插件 / 文件解析

- 更新：HTTP 源、无签名、允许降级、渠道参数可改、包内路径穿越（zip slip）。
- 插件/扩展：未签名、可从任意源安装、加载路径可控、插件权限过大。
- 文件解析：命令注入（文件名/路径拼命令行）、路径穿越、反序列化（见 `deserialization.md`）、解析器已知 CVE；内存类方法见 `memory-safety.md`。
- 只崩不执行 → DoS，不写。

## 8. 引擎版本与利用

- 取版本：UA、`process.versions`（Electron/Node）、`libcef.dll` 文件版本、`chrome://version`（能开 DevTools 时）。
- 记录：Chromium/V8 版本、32/64 位、沙箱、`--disable-web-security`、`--ignore-certificate-errors`。
- 引擎层不是固定 CVE 清单：先算目标 Chromium 基线，把基线之后的**全部** Chrome 安全修复当候选，再按组件/构建/投递过滤；CEF 见 `cef-trust-boundaries.md` §1，Electron 见 `electron-trust-boundaries.md` §1。
- 公开 1day 必须对上版本 + 位数 + 沙箱；对不上就只能写“潜在”。32 位和 64 位 PoC 通常不能互换。
- 先有投递再谈 1day；渲染进程崩溃 ≠ 代码执行。

## 9. 映射模板（每个目标复制一张）

| # | 输入面 | 载体/入口 | 谁能产生 | 疑似 sink | 状态 | 下一步 |
|---|---|---|---|---|---|---|
| 1 |  |  |  |  | Go/Stop/待验证 |  |
| 2 |  |  |  |  |  |  |

状态口径：`A` 动态已证 / `B` 静态强证据 / `C` 待验证 / `D` 动态反证 / `S` sink only。
