# 客户端黑盒攻击面清单

> 范围：只交付**可远程触达**的漏洞——攻击者在自己的机器上构造 URL / Deep Link / 聊天消息 / 网络包 / 文件，通过网络送达受害者即可触发。  
> 需要已登录受害者账号、物理接触、本机恶意软件才能触发的，算本地缺陷；唯一例外是跨权限边界的提权/沙箱逃逸（`SKILL.md` §9.1）。  
> 本文件是“看什么”；方法、案例、工具、报告分别见 `case-library.md`、`windows-toolchain.md`、`report-format.md`。

## 1. 框架面

| 框架 | 识别 | 重点入口 | 先看什么 |
|---|---|---|---|
| Electron | `resources/app.asar`、`electron*.dll`、`--type=renderer` | `ipcRenderer`/`ipcMain`、preload、`<webview>`、`shell.openExternal` | `nodeIntegration`、`contextIsolation`、`sandbox`、`fuses` |
| CEF / CefSharp | `libcef.dll`、`CefSharp*.dll`、`*Subprocess.exe` | `CefMessageRouter`、JS 对象、`OnProtocolExecution`、scheme handler | 协议白名单、共享内存、`allow_os_execution` |
| WebView2 | `msedgewebview2.exe`、`WebView2Loader.dll`、UA `Edg/` | `chrome.webview.postMessage`、`hostObjects` | host object 方法、消息来源校验 |
| Qt WebEngine | `Qt*WebEngineCore.dll`、`QtWebEngineProcess.exe` | `QWebChannel`、`runJavaScript`、自定义 scheme | 暴露的 QObject、导航限制 |
| NW.js | `nw.dll`、`nw.pak`、`package.json` | DOM 里直接 `require` | `node-remote`、`--mixed-context` |
| Tauri | Win 用 WebView2、mac 用 WKWebView；Rust 主程序 | `invoke`、asset/shell/fs scope | `tauri.conf.json`/capabilities、命令参数 |
| WPF / WinForms | .NET 程序集、`PresentationFramework`/`System.Windows.Forms`；常内嵌 WebView2/CEF | 本地 HTTP/WS、命名管道、JS bridge、文件解析 | 反编译 .NET、看 IPC/端口/文件解析 |
| WinUI3 / Windows App SDK | `Microsoft.WindowsAppRuntime`、WebView2 | WebView2 消息、本地服务、打包/更新 | 同 WebView2 + 应用包边界 |

## 2. 自定义协议 / Deep Link

看什么：

- 注册位置：Windows `HKCU\Software\Classes\<scheme>` / `HKCR`；macOS `CFBundleURLTypes`；Linux `.desktop`。
- 参数名：`url`、`open`、`openUrl`、`webview`、`file`、`path`、`cmd`、`command`、`install`、`download`、`foldername`、`id`、`token`。
- 解析链：URL 解码 → 参数拆分 → 白名单/前缀检查 → 落地到 `loadURL`/`ShellExecute`/文件操作/下载。
- 外部投递：浏览器 `<a href="scheme://...">`、聊天消息、文档内链、二维码、其他 App 拉起。
- 判负：只有本机 Win+R/终端能起，没有外部投递路径 → 不算。

常见坑：

- 只校验前缀：`trusted.com@evil.com`、`trusted.com.evil.com`、`trusted.com%2eevil.com`。
- 双重编码、base64、嵌套 scheme、`#` 后内容、`%00`、反斜杠、大小写、超长截断。
- 参数拼命令行：空格/引号导致参数注入。
- `file://`/UNC/`javascript:`/`data:` 未拦。

## 3. 侦听端口

枚举：

```powershell
Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess
Get-CimInstance Win32_Process | Where-Object {
  $_.ProcessId -in (Get-NetTCPConnection -State Listen).OwningProcess
} | Select-Object ProcessId,Name,CommandLine
```

看什么：

- 绑定地址：`127.0.0.1` vs `0.0.0.0`/`::`；非回环 = 可能被远程/同 LAN 访问。
- 协议：HTTP、WebSocket、gRPC、私有 TCP/UDP。
- 鉴权：token/cookie/Origin/Referer 校验；无鉴权 = 直接功能调用。
- 路由：`/api/exec`、`/api/ping`、`/api/go-to`、`/download`、`/json`（CDP）。
- 参数：命令拼接、URL 白名单、路径拼接、`@evil.com` 绕过。
- 路径遍历：`/../../../Windows/win.ini`；curl 用 `--path-as-is` 保留 `..`。
- CDP：`/json`、`/json/list`、`/json/version`；默认只绑回环，但无 Origin 校验时网页可打。

## 4. 进程与模块

- 主进程、渲染子进程、工具/服务进程、更新进程；谁有网络、谁解析文件、谁监听端口。
- 模块：以**实际加载清单**为准（OpenArk `ps_module_list` / Process Explorer），不看安装目录里有哪些文件；`libcef.dll`、`msedgewebview2.exe`、`Qt*WebEngineCore.dll`、`ffmpeg*.dll`、`libwebp*.dll`、`pdfium.dll`、`*.node` 出现了才算数。
- 命令行：`--type=renderer`、`--remote-debugging-port`、`--inspect`、`--no-sandbox`、`--user-data-dir`。
- 句柄：文件、命名管道、Section（共享内存）、事件。
- 工具：OpenArk（`ps_*`/`mem_*`/`net_*`）、Process Explorer、`Get-CimInstance`。

## 5. 功能面

| 功能 | 输入 | 重点 |
|---|---|---|
| 社交/IM | 消息、富文本、图片、语音、视频、文件、名片、公告、资料页 | XSS、文件解析、自动预览、链接白名单、鉴权头泄露 |
| 文档 | pdf/doc/docx/ppt/pptx/xlsx/md/html | 解析器内存漏洞、XXE、外链加载、宏/脚本、路径穿越 |
| 图片 | png/jpg/jpeg/gif/webp/avif/heic/svg | 解码器溢出、SVG 脚本、缩略图自动解析 |
| 音视频 | mp3/mp4/avi/mkv/flac/字幕 | 解码器溢出、封面/字幕解析、自动播放 |
| 浏览器 | URL/html/xml/js | file 域、特权域、CSP、JS bridge、下载 |
| 投屏/远控 | 端口、协议、画面/输入通道 | 未授权连接、命令注入、协议解析、DoS |
| 文件传输 | 任意文件、文件名、保存路径 | 路径穿越、下载执行、覆盖启动项、类型混淆 |
| 更新/插件 | 更新包、插件包、配置 | 签名/降级、zip slip、加载路径、权限 |

## 6. JS Bridge

- 枚举：`window` 上所有非标准对象/函数；Electron `require`/`process`/preload 暴露；CEF `cefQuery`/注册对象；WebView2 `chrome.webview.hostObjects`；Qt `QWebChannel`；Tauri `__TAURI__`。
- 逐个方法看：参数类型、长度、路径、URL、命令、文件读写、剪贴板、cookie/token。
- 特权域：方法是否只在某些 origin 可用；能否用 `file://`、`about:blank`、`data:`、iframe、`window.open` 绕过。
- 输出：把方法名、参数、返回值、可用域记到攻击面表。

## 7. 文件类型

| 类型 | 看什么 |
|---|---|
| `.exe` / `.dll` | 版本、导入、签名、DLL 侧加载、更新/插件加载路径 |
| `.asar` | `asar list/extract`；`package.json` 的 `main`/`preload`；IPC、协议、端口、密钥 |
| `.config` / `.json` / `.xml` | 更新源、白名单、特权域、密钥、调试开关、插件配置 |
| `.js` / `.html` | 内嵌页面、JS bridge 调用、file 域、外部 URL、CSP |
| `.pak` | 资源包；解包看内嵌页面/脚本/配置 |
| 文档/图片/音视频 | 解析器、自动预览、缩略图、解码器版本 |

## 8. 鉴权

- 客户端如何鉴权：cookie、token、ticket、设备指纹、签名、时间戳。
- 鉴权参数放在哪：header、query、body、本地存储、命名管道。
- 重点：外部页面/消息能否让客户端把鉴权参数带到攻击者 URL（`@evil.com`、重定向、预览抓取）。
- 白名单/特权域：是否只按字符串前缀/正则；能否用子域、`@`、大小写、编码绕过。
- 只影响自己账号的不算越权；要跨用户/跨租户/提升权限。

## 9. 逆向要求

- 静态：`rabin2`、Ghidra、IDA Pro；看导入、字符串、交叉引用、反编译。
- 动态：frida、cdb、x64dbg、WinDbg、procdump；看参数、返回值、调用栈、堆。
- .NET：dnSpy/ILSpy（若可用）、Ghidra；看程序集、XAML、IPC、序列化。
- 结论要落到函数/行号/调用链；只靠界面猜测不算。

## 10. 攻击面表模板

| # | 攻击面 | 触发方式 | 框架/类型 | 可能漏洞 | 状态 |
|---|---|---|---|---|---|
| 1 |  |  |  |  | Go/Stop/待验证 |

## 11. 判负清单

- 只有本机 Win+R/终端能触发，没有浏览器/聊天/文档/其他 App 的投递路径。
- JS bridge 只在特权域可用，且没有特权域 XSS/绕过。
- URL/路径在更早的地方已被规范化/白名单过滤（实际到不了 sink）。
- 命中系统浏览器，不是客户端内嵌引擎。
- 只崩不执行，且没有可控 primitive。
- 本地同用户能力，没有跨权限边界。
