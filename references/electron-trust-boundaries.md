# Electron 信任边界审计（引擎 / 框架 / 绑定 / 配置）

> 适用：Electron 应用、electron-builder / Forge 打包、`@electron/remote`（旧）。  
> 核心：主进程拥有完整 Node/OS 权限；渲染进程默认应视为不可信。所有渲染 → 主进程、页面 → Node/OS、输入 → 调试/OS 的路径都要设防。  
> CVE 于 2026-10-22 用 NVD API（CPE `electronjs:electron`）核对；示例不是清单。

## 0. 四层信任边界

| 层 | 不可信 → 可信 | 典型入口 | 审计点 | 对应闸门 |
|---|---|---|---|---|
| **引擎** | 网页 → V8 / Blink | BrowserWindow / WebContentsView / `<webview>` 加载的页 | Chromium 基线、sandbox、1day | G1 / G2（sink） |
| **框架** | 渲染进程 → 主进程 | `ipcRenderer` / `ipcMain`、`contextBridge`、MessagePort、`<webview>`、service worker | sender/frame 校验、通道白名单、参数 schema | G2 |
| **绑定** | 页面 JS → Node / OS | `nodeIntegration`、preload、`contextBridge` 暴露对象、`shell`、`protocol` | 暴露面最小化、原始类型参数、路径/URL 校验 | G0 / G1 |
| **配置** | 外部输入 → 调试 / OS | fuses、`--inspect`、`--remote-debugging-port`、`ELECTRON_RUN_AS_NODE`、deep link、导航 | 生产 fuse、白名单、弹窗/导航限制 | G0 |

与 CEF 最大的差别：**Electron 主进程没有被沙箱包着**。渲染进程一旦拿到 Node（`nodeIntegration` 或桥缺陷），通常不需要再打沙箱逃逸。

## 1. 引擎层（网页 → V8 / Blink）

Electron 打包 Chromium，继承的是 **Chromium 的整个漏洞历史**；下面只是示例，不是清单。

### 1.1 先算基线

- `process.versions` 直接给 `electron`、`chrome`、`node`、`v8`；以 **`chrome`** 为 Chromium 基线。
- 打包产物：`resources/app.asar`、`node_modules/electron/package.json`、electron-builder 配置里的 `electronVersion`。
- 运行时拿不到 `process`：看 UA 里的 `Electron/x`、安装目录里的 `chrome_100_percent.pak` / `icudtl.dat` / `v8_context_snapshot.bin`、能开 DevTools 时的 `chrome://version`。
- Electron 官方只维护最近 3 个 major；更老的版本不再修。基线滞后 = 继承整段 Chromium 漏洞史。

### 1.2 枚举候选

| 来源 | 用法 |
|---|---|
| Chrome Releases | `chromereleases.googleblog.com` 的 Stable Channel Update，按版本列 CVE |
| NVD API | `keywordSearch=Chrome` / `Chromium`；或 CPE `cpe:2.3:a:google:chrome` |
| Electron 公告 | GitHub `electron/electron` Security Advisories、releases 说明、OSV |
| NVD Electron | CPE `cpe:2.3:a:electronjs:electron`，补 Electron 框架自身的 CVE |
| 组件公告 | V8 / Blink / Skia / PDFium / ANGLE / FFmpeg 的独立修复 |

### 1.3 过滤

1. **组件在不在**：V8、Blink、WebGL/ANGLE、WebAudio、WebCodecs、PDFium、Skia、媒体解析、Mojo。Chrome UI、Chrome 更新器、企业策略这些 Electron 里通常没有。
2. **构建开没开**：`sandbox`、`nodeIntegration`、`contextIsolation`、32/64 位、JIT、GPU、`webviewTag`。
3. **能不能投递**：攻击者页面是否真的被这个应用的 BrowserWindow/WebContentsView 加载；只走系统浏览器不算。
4. **能不能利用**：公开 PoC / 在野、目标版本、缓解措施（ASLR/CFG/CET）、渲染进程沙箱。

### 1.4 示例（Chromium 侧，不是清单）

| CVE | 组件 | 影响版本 | 类型 | NVD |
|---|---|---|---|---|
| CVE-2025-8010 | V8 | Chrome < 138.0.7204.168 | 类型混淆 | 8.8 |
| CVE-2025-8011 | V8 | Chrome < 138.0.7204.168 | 类型混淆 | 8.8 |
| CVE-2024-7971 | V8 | Chrome < 128.0.6613.84 | 类型混淆 | 8.8 / 9.6 |

判据：目标 Electron 打包的 Chromium 是否 `<` 修复版本；不是只看 Electron major。

## 2. 框架层（渲染进程 → 主进程）

| 接口 | 风险 | 必查 |
|---|---|---|
| `ipcMain.on` / `ipcMain.handle` | 任意渲染进程都能发消息 | `event.senderFrame` 的 URL/origin、通道白名单、参数 schema |
| `contextBridge.exposeInMainWorld` | 暴露面过大 | 只暴露最小函数；参数只收原始类型；不整体暴露 `ipcRenderer` / `shell` |
| `<webview>` | guest 权限继承 | `will-attach-webview` 删 `preload` / `nodeIntegration`；`webviewTag` 关闭 |
| `window.open` / `setWindowOpenHandler` | 子窗口权限提升 | target name 作用域；`overrideBrowserWindowOptions` 只给可信页 |
| `protocol.handle` / `registerSchemesAsPrivileged` | 自定义 scheme 跨域/路径 | `corsEnabled`、`supportFetchAPI`、路径规范化 |
| `net.fetch` / `net.request` | 重定向 scheme | 限制 `http(s)`，拒绝 `file:` / 自定义 |
| `webContents.executeJavaScript` | 注入 | 不拼不可信字符串 |
| service worker | 内部 IPC 冒充 | 来源校验、消息通道隔离 |

### 2.1 框架层 CVE 示例

- **CVE-2026-102677**（< 42.10.0 / 43.5.0 / 44.0.0-beta.6，8.8 / 7.8）：sandboxed preload code cache 未校验缓存归属；被攻破的渲染进程可写入缓存，之后在更高权限的 preload 上下文执行。
- **CVE-2026-34765**（< 39.8.5 / 40.8.5 / 41.1.0 / 42.0.0-alpha.5，8.8 / 6.0）：`window.open()` 的 target name 未按 browsing context group 作用域；一个渲染进程可导航另一个渲染进程开的子窗口，继承其更高权限的 `webPreferences`。
- **CVE-2026-70608**（< 39.8.10 / 41.10.3 / 42.0.1，7.2）：sandboxed iframe 没有 `allow-popups`，仍可通过 OpenURL 路径开窗或触发 `setWindowOpenHandler`。
- **CVE-2026-70604**（< 39.8.10 / 40.9.3 / 41.4.0 / 42.0.0，7.4）：自定义 scheme 设了 `supportFetchAPI: true` 但没设 `corsEnabled: true`，不受 CORS 限制，远程页可 `fetch()` 读完整响应。

### 2.2 审计要点

- 每个 `ipcMain` handler 先验 sender：`event.senderFrame` 存在、URL/origin 在白名单、不是被导航后的页面；不要只看通道名。
- 参数做 schema 校验：类型、长度、枚举、路径；不要直接 `JSON.parse` 后透传。
- 不把 `ipcRenderer` 整体暴露给页面；用 `invoke` 包装具体命令。
- `will-attach-webview` 强制删掉 `preload` / `nodeIntegration`；`setWindowOpenHandler` 默认 `deny`。

## 3. 绑定层（页面 JS → Node / OS）

### 3.1 配置矩阵

| 配置 | 安全值 | 风险 |
|---|---|---|
| `nodeIntegration` | `false` | `true` 时页面可直接 `require('child_process')` |
| `contextIsolation` | `true` | `false` 时 preload 与页面共享上下文 |
| `sandbox` | `true` | `false` 时渲染进程可触达更多系统能力 |
| `nodeIntegrationInWorker` | `false` | worker 拿到 Node |
| `nodeIntegrationInSubFrames` | `false` | iframe 拿到 Node |
| `webviewTag` | `false` | `<webview>` 权限继承 |
| `enableRemoteModule` / `@electron/remote` | 禁用 | 页面直接拿主进程对象 |
| `preload` | 最小暴露 | 暴露危险函数等于开后门 |

### 3.2 危险 API

- `shell.openExternal(url)` / `shell.openPath(path)`：scheme/path 白名单；拒绝内嵌 null byte；realpath 后再判。
- `protocol.handle` / `registerFileProtocol`：路径遍历、目录边界。
- `app.setAsDefaultProtocolClient` + `open-url` / `second-instance`：deep link 参数解析。
- preload 暴露的 fs / child_process / clipboard / 文件选择器。
- `webContents.executeJavaScript` / `insertCSS`：不可信字符串注入。

### 3.3 绑定层 CVE 示例

- **CVE-2026-70601**（< 39.8.9 / 40.9.2 / 41.2.2 / 42.0.0-beta.5，7.5）：通过 `contextBridge` 暴露 Promise 返回函数，可导致 context isolation bypass；不可信页面拿到 preload world 的全部能力；无 sandbox 或 `nodeIntegration` 时升到 Node。
- **CVE-2026-70610**（< 39.8.9 / 40.9.2 / 41.2.2 / 42.0.0-beta.4，5.4）：跨 `contextBridge` 的对象带攻击者影响的 prototype，可对 preload 做原型污染；preload 读属性不做 own-property 检查时中招。
- **CVE-2026-70603**（< 39.8.6 / 40.9.0 / 41.1.1 / 42.0.0-beta.1，6.0）：`shell.openPath()` 未拒绝内嵌 null byte；只做字符串校验的路径可绕过。
- **CVE-2026-102676**（< 41.10.6 / 42.9.2 / 43.4.1 / 44.0.0-beta.5，9.8 / 8.3）：`<webview>` guest 可在 unsandboxed embedder 关闭 Node 的情况下，为 Web Worker 开 `nodeIntegrationInWorker`。
- **CVE-2026-34775**（< 38.8.6 / 39.8.4 / 40.8.4 / 41.0.0，9.8 / 6.8）：`nodeIntegrationInWorker` 作用域错误，配置为 `false` 的 frame 仍可能拿到 Node。

### 3.4 审计要点

- `contextBridge` 只暴露函数，参数尽量用原始类型；对象参数检查 own property；不返回特权对象。
- 路径：拒绝 null byte，`path.resolve` / realpath，目录分隔符边界，白名单。
- URL：scheme/host 白名单；`file:`、`smb:`/UNC、自定义协议单独判断。
- 不把 `shell`、`fs`、`child_process`、`ipcRenderer` 整体暴露给页面。

## 4. 配置层（外部输入 → 调试 / OS）

### 4.1 Fuses

| Fuse | 生产建议 | 风险 |
|---|---|---|
| `RunAsNode` | 关 | `ELECTRON_RUN_AS_NODE=1` 把应用当 Node 跑 → 本地代码执行 |
| `EnableNodeCliInspectArguments` | 关 | `--inspect` 打开主进程 Node inspector → 主进程代码执行 |
| `EnableNodeOptionsEnvironmentVariable` | 关 | `NODE_OPTIONS` 注入 `--require` → 本地代码执行 |
| `OnlyLoadAppFromAsar` | 开 | 防止从解包目录/替换的 app 加载 |
| `EnableEmbeddedAsarIntegrityValidation` | 开 | ASAR 完整性校验 |
| `GrantFileProtocolExtraPrivileges` | 关 | `file://` 获得额外权限 |

审计：用 `@electron/fuses` 的读取命令或解析可执行文件，确认生产包的 fuse 状态，不要只看源码配置。这些 fuse 打开时提供的是本地代码执行能力；同用户不报，跨权限边界才按提权报。

### 4.2 调试接口

- `--remote-debugging-port` 默认只绑 `127.0.0.1`；DevTools 有 Host 校验，较新 Chromium 的 WebSocket 还要 Origin 白名单。默认配置下是**本地能力**。
- 例外：若能从低权限上下文跨到高权限（普通用户→管理员/SYSTEM、沙箱渲染进程→主进程），按本地提权上报；同用户可达不报。
- CEF/Electron 的 CDP 主要是渲染进程页面 JS；是否到 OS 取决于渲染进程有没有 Node/桥。
- `--inspect` 是**主进程 Node inspector**：在 `EnableNodeCliInspectArguments` 开启时，拿到它就是主进程代码执行，比渲染进程 CDP 更直接。
- `ELECTRON_RUN_AS_NODE` / `NODE_OPTIONS` 同理：本地能力，除非能由外部输入设置启动参数/环境变量。

### 4.3 Deep link 与导航

- `app.setAsDefaultProtocolClient('app')`；macOS `open-url`，Windows/Linux `second-instance` argv。URL 来自外部，按不可信输入解析；scheme/host 白名单，不要直接交给 `shell`。
- `will-navigate` / `will-redirect` / `setWindowOpenHandler`：默认拒绝外部导航和新窗口；允许时只给可信 origin。
- `webviewTag` 关闭；必须用时在 `will-attach-webview` 清理权限。
- `session.setPermissionRequestHandler` / `setPermissionCheckHandler`：默认拒绝摄像头、麦克风、通知、openExternal 等。

### 4.4 放大项（不是漏洞本身）

- `webSecurity: false`、`allowRunningInsecureContent`、`--no-sandbox`、`disable-site-isolation-trials`、`nodeIntegration: true`。
- 自动更新未验签 / 允许降级：独立边界，通常按供应链或网络位置处理。

## 5. 审计顺序

1. **认版本与 fuses**：`process.versions`、`app.asar`、fuse 状态。
2. **找 IPC / contextBridge / webview**：所有 `ipcMain` handler、暴露对象、`<webview>`、`setWindowOpenHandler`。
3. **找页面 → Node/OS**：`nodeIntegration`、preload、`shell`、`protocol`、deep link。
4. **找调试/配置开关**：`--inspect`、`--remote-debugging-port`、`ELECTRON_RUN_AS_NODE`、`NODE_OPTIONS`、权限 handler。
5. **回到 G0–G3**：谁是互联网可控输入？进的是不是这个应用的渲染进程？能到什么能力？

## 6. 一句话

Electron 的风险集中在四个跨越点：**网页 → 引擎、渲染 → 主进程、页面 → Node/OS、输入 → 调试/OS**。  
引擎层靠版本回溯，IPC/绑定层靠 sender 校验和最小暴露，配置层靠 fuses 和生产开关。
