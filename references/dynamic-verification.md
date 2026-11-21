# 动态验证配方（通用客户端）

> 目标：先回答“进没进客户端”，再回答“进去能做什么”。  
> 默认测试账号 + 私有环境；测完恢复页面、关窗口、停服务。  
> Windows 工具命令（rabin2/asar/frida/cdb/procdump/Ghidra）见 `windows-toolchain.md`。

## 0. 纪律

- 只在私有测试环境（测试群/测试频道/自己的设备）发内容，不要往公开环境发。
- 一次只测一个候选；记录 UA、进程、端口、target、桥输出。
- 最小影响：读自己的 uid、写自己的临时文件、本机弹计算器；不删别人数据、不改别人配置。
- 测前记录登录态/端口；测后恢复。客户端可能重启，登录态可能掉。
- 本地发现默认不报；只有跨权限边界（提权/沙箱逃逸）才按本地提权上报。

## 1. 认进程与引擎

Windows：

```powershell
# 带调试/渲染参数的命令行
Get-CimInstance Win32_Process |
  Where-Object { $_.CommandLine -match 'remote-debugging-port|--inspect|--type=renderer|user-data-dir' } |
  Select-Object ProcessId, Name, CommandLine | Format-List

# 关键模块（先按进程名收窄，避免遍历系统进程报 Access denied）
Get-Process |
  Where-Object { $_.ProcessName -match '<目标进程名>' } |
  ForEach-Object { $_.Modules } |
  Where-Object { $_.ModuleName -match 'libcef|CefSharp|electron|webview2|Qt.*WebEngine|nw\.dll|node\.dll' } |
  Select-Object ModuleName, FileName -Unique

# 监听端口
Get-NetTCPConnection -State Listen |
  Select-Object LocalAddress, LocalPort, OwningProcess |
  Sort-Object LocalPort
```

macOS / Linux：

```bash
ps aux | grep -iE 'electron|cef|webview|qtwebengine|nw\.js|tauri'
lsof -nP -iTCP -sTCP:LISTEN          # macOS
ss -lntp                              # Linux
tr '\0' ' ' < /proc/<pid>/cmdline     # Linux 命令行
```

安装目录怎么看：

- Electron：`resources/app.asar`、`resources/app/package.json`；版本基线直接读 `process.versions`（electron/chrome/node/v8），fuses 用 `npx @electron/fuses read --app <应用路径>`。
- CEF/CefSharp：`libcef.dll`、`CefSharp.Core.dll`、`locales/`、`*.pak`。
- WebView2：`WebView2Loader.dll`；用户数据目录通常有 `EBWebView/`。
- Qt：`Qt5WebEngineCore.dll` / `Qt6WebEngineCore.dll` + `QtWebEngineProcess.exe`。
- NW.js：`nw.dll` / `nw.pak` + `package.json`。

Windows 上还可接：

- **OpenArk**（MCP `ps_*` / `mem_*` / `net_*`）：枚举进程、模块、句柄、内存区、监听端口；找第三方解析库和 IPC/共享内存入口。**模块梳理以 `ps_module_list` 的实际加载结果为准**（主进程 + 每个子进程分别拉一次，按 name/company 过滤出非系统模块）——安装目录里躺着但没加载的 DLL 不纳入攻击面；只有确认动态加载路径（更新、插件、延迟加载）才补进列表。
- **IDA Pro**（MCP `idalib_*`）：看导入、交叉引用、反编译、数据流，定位“输入长度 → 分配 → 拷贝”的路径。
- 两者只辅助本地观察/静态定位，不替代外部可达性判断；细化流程见 `memory-safety.md` §4 的 Windows 工具链。

## 2. 打开调试通道（本地研究用，不作为漏洞）

| 引擎 | 做法 |
|---|---|
| Chromium 系 | 启动参数 `--remote-debugging-port=9222`；较新版本再加 `--remote-allow-origins=*` 才能从任意页连 WebSocket |
| Electron | 同上；主进程 Node 调试 `--inspect=5858`（`chrome://inspect`） |
| WebView2 | 启动前设 `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--remote-debugging-port=9222`；用户数据目录下的 `DevToolsActivePort` 也可能给出端口 |
| CEF | 命令行 `--remote-debugging-port`，或产品配置里的 `remote_debugging_port`；有的产品只在测试版/调试构建开启 |
| Qt WebEngine | 一般支持 Chromium 参数，但产品常移除；先看命令行与配置 |
| 无参数入口 | 找产品自己的 devtools 开关、配置文件、注册表项、测试版；找不到就换 UA 金丝雀/抓包，不要死磕 |

连上后：

```powershell
Invoke-RestMethod http://127.0.0.1:9222/json/version
Invoke-RestMethod http://127.0.0.1:9222/json/list |
  Select-Object id, title, url, webSocketDebuggerUrl
```

注意：

- 端口每次启动可能变化；新窗口可能是**新端口**，`/json/list` 只列当前实例的页面。
- 调试端口是**本地能力**，只用来观察页面/桥；不要写成外部漏洞。
- 多实例时按 `--user-data-dir` / 进程 PID 对上是哪个客户端。

## 3. UA 金丝雀

起一个只记录 UA 的本地服务：

```python
# canary_server.py — 记录 UA / Referer / 路径；跨机器测试时把 127.0.0.1 改成 0.0.0.0
from http.server import BaseHTTPRequestHandler, HTTPServer

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        ua = self.headers.get("User-Agent", "")
        ref = self.headers.get("Referer", "")
        with open("canary_hits.log", "a", encoding="utf-8") as f:
            f.write(f"{self.client_address[0]}\t{ua}\t{ref}\t{self.path}\n")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"<h1>canary</h1>")

    def log_message(self, *args):
        pass

HTTPServer(("127.0.0.1", 8084), H).serve_forever()
```

判据：

| UA 特征 | 来源 |
|---|---|
| 含 `Electron/x.y.z` | Electron 渲染进程（除非产品改了 UA） |
| 产品 token + Chromium 版本，无 `Edg/` | CEF / CefSharp |
| 含 `Edg/<version>` | WebView2（或系统 Edge） |
| 裸 Chrome，无产品 token | 可能是 Qt WebEngine，也可能是系统 Chrome —— 看进程 |
| 正常 Chrome/Edge/Firefox UA，无产品 token | 系统浏览器，**路径判负** |

只认“客户端引擎”的 UA；同时记录来源 IP、Referer、路径，确认是哪个入口触发的。  
跨机器测试时服务要监听 `0.0.0.0`，并确认防火墙放行。

## 4. 桥探测

先看对象，再调只读方法；不要只看 `typeof`。

```js
({
  electron: !!(window.process && window.process.versions && window.process.versions.electron),
  nodeRequire: typeof window.require,
  webview2: !!(window.chrome && window.chrome.webview),
  qt: !!(window.qt && window.qt.webChannelTransport),
  tauri: typeof window.__TAURI__ !== 'undefined' || typeof window.__TAURI_INTERNALS__ !== 'undefined',
  cefQuery: typeof window.cefQuery,
  nw: typeof window.nw
})
```

各引擎的只读验证：

```js
// Electron（nodeIntegration 开时）
window.require && window.require('process').versions

// WebView2 host objects（先看有哪些；逐级判空，避免 ReferenceError）
window.chrome && window.chrome.webview && window.chrome.webview.hostObjects &&
  Object.keys(window.chrome.webview.hostObjects)

// Qt WebChannel（页面没加载 QWebChannel 库时会 ReferenceError，先判 typeof）
typeof QWebChannel !== 'undefined' &&
  new QWebChannel(window.qt.webChannelTransport, ch => console.log(Object.keys(ch.objects)))

// Tauri（只调实际存在的只读命令，名字按产品改）
window.__TAURI__ && window.__TAURI__.invoke && window.__TAURI__.invoke('<只读命令名>')

// CEF（CefMessageRouter）
window.cefQuery && cefQuery({ request: 'getVersion', onSuccess: r => console.log(r), onFailure: e => console.log(e) })
```

注意：

- 有对象 ≠ 能用：有的对象只是壳，方法调用才报错。
- 只调 `getUid` / `getVersion` / 票据长度这类只读方法；不调写文件、下载、执行。
- 返回值里出现票据/机器码：只记长度和字段名，不复述内容。

## 5. 协议处理器验证

触发方式（按外部可达顺序）：

1. 浏览器页面 `<a href="scheme://...">` 或 302 跳到该 scheme。
2. 聊天消息/群公告里的链接（用两个测试账号，A 发 B 点）。
3. 二维码（自己生成，客户端扫）。
4. 系统分享/其他 App 拉起。

不要只做 4；终端 `start scheme://...` 能起不代表互联网可达。

一次只改一个参数，观察：

- 是否拉起客户端；是否新开内嵌窗口；是否落到系统浏览器；是否弹确认框。
- 新窗口的 UA/端口/target；父进程是谁。
- 原始 URL、解码后 URL、最终加载的 URL 各是什么。

解析测试清单：双重编码、base64、嵌套 scheme、`@`、`\`、`%00`、`..`、超长、大小写、前后空白、`#` 后内容、引号/空格导致的命令行参数注入。

## 6. 投递验证

| 入口 | 做法 | 记录 |
|---|---|---|
| 用户间内容 | A 号发 B 号；B 端点开 | B 端 UA/进程/窗口 |
| 公告/资料/分享卡片 | 测试群/测试频道，改完恢复 | 改动前后截图 |
| 二维码 | 自己生成，客户端扫 | 是否二次确认、落地 URL |
| 网页跳转 | 外部页 302 / `target=_blank` | 客户端是否跟随 |
| 运营/广告 | 没有权限就不要伪造 | 写“需运营权限”并降级 |

纪律：一次只测一个字段；不要同时改多个入口；不要在公开环境留测试内容。

## 7. 影响验证（最小化）

| 级别 | 做什么 | 不做什么 |
|---|---|---|
| L1 | `document.title` / DOM marker | 不弹窗骚扰 |
| L2 | 只读桥方法，返回自己的 uid/版本 | 不调文件/命令类方法 |
| L3 | 只读自己的票据，只记长度 | 不导出、不复述 |
| L4 | 写自己的临时文件、本机弹计算器 | 不写系统目录、不删他人文件 |
| L5 | 不默认验证持久化 | 不加启动项/计划任务/服务 |

## 8. 崩溃 / 重启 / 登录态

- 先记 PID、端口、页面 URL；崩溃后端口可能变化，target 会消失。
- 掉登录态先恢复登录，再继续；不要在未登录状态下把“没桥”当结论。
- 不反复 fuzz 已知会崩的参数；渲染进程崩溃 ≠ 代码执行；内存类崩溃的 triage 见 `memory-safety.md`。
- 崩溃线程栈可用 OpenArk `ps_thread_stack` 看；崩溃地址回到 IDA 伪代码定位根因。
- 动态调试：x64dbg（用户态 API/内存断点）与 WinDbg（`!analyze -v`、`!heap -p -a`、PageHeap、TTD）；细节见 `memory-safety.md` §4。
- 客户端可能有多实例，确认测的是同一个。

## 9. 清理与证据

清理：

- 恢复被导航的页面；`window.close()` 关闭测试窗口。
- 停本地 8084/调试服务；删除测试消息、临时文件。
- 恢复测试群/频道公告/资料卡。
- 不在公开环境留痕。

证据：

- UA 日志（`canary_hits.log`）。
- 进程命令行 / 端口 / `/json/list` 输出。
- 桥返回值（脱敏）、页面 marker 截图。
- 原始 URL、解码后 URL、最终 URL。
- 时间线：谁在什么时候从哪个入口触发。

脱敏：票据只写长度；cookie/token/机器码不复述全文。
