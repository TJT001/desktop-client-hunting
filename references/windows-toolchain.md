# Windows 客户端工具链

> 默认在测试 VM/快照里操作，只对授权目标。命令参数以工具自带 `-h`/`-?` 为准。  
> 运行时的进程/模块/句柄枚举还可接 OpenArk，静态定位可接 IDA Pro，动态调试可接 x64dbg/WinDbg（见 `memory-safety.md` §4）。

## 0. 工具分工

| 工具 | 用途 | 典型入口 |
|---|---|---|
| PowerShell / cmd | 进程、模块、端口、注册表、文件枚举 | 主战 |
| python | HTTP/WS 客户端、协议构造、日志服务、脚本化 | 主战 |
| `rabin2` | PE 信息、导入、符号、字符串、段 | `<tools>\radare2\bin\rabin2.exe` |
| `asar` | Electron 包解包/列举 | `asar list/extract` |
| `curl.exe` | 本地端口、路径遍历、CDP HTTP 端点 | 系统自带 |
| `frida` / `frida-tools` | 运行时 hook、参数/返回值追踪 | pip 安装版 |
| `cdb.exe` | 命令行调试、崩溃分析、脚本断点 | Windows SDK Debugging Tools |
| `procdump.exe` | 崩溃/异常转储 | `<tools>\Procdump\` |
| Ghidra | 反编译/反汇编、交叉引用 | `<tools>\ghidra\` |
| OpenArk | 进程/模块/句柄/内存/内核枚举 | MCP `ps_*`/`mem_*`/`net_*` |
| IDA Pro | 静态定位、数据流、补丁 diff | MCP `idalib_*` |
| x64dbg / WinDbg | 用户态/内核动态调试、TTD | GUI/命令行 |

## 1. PowerShell / cmd / Python

```powershell
# 进程与命令行
Get-CimInstance Win32_Process | Select-Object ProcessId,Name,CommandLine

# 模块
Get-Process <name> | ForEach-Object { $_.Modules } |
  Select-Object ModuleName,FileName -Unique

# 监听端口
Get-NetTCPConnection -State Listen |
  Select-Object LocalAddress,LocalPort,OwningProcess

# 协议注册
reg query "HKCU\Software\Classes" /s /f "URL Protocol"
reg query "HKLM\Software\Classes" /s /f "URL Protocol"

# 关键文件
Get-ChildItem -Recurse -Include *.asar,*.pak,*.json,*.xml,*.config |
  Select-Object FullName,Length
```

Python 常用：

```python
# 本地回环日志服务；用于确认请求是否真的到本机
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        print(self.client_address, self.headers.get("User-Agent"), self.path, flush=True)
        self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
    def log_message(self, *a): pass
HTTPServer(("127.0.0.1", 8080), H).serve_forever()
```

## 2. rabin2

```bat
rabin2 -I app.exe        :: 架构/位数/类型
rabin2 -i app.exe        :: 导入
rabin2 -s app.exe        :: 符号
rabin2 -z app.exe        :: 字符串
rabin2 -S app.exe        :: 段
rabin2 -e app.exe        :: 入口
rabin2 -M app.exe        :: main
rabin2 -l app.exe        :: 依赖库
```

```bat
rabin2 -z app.exe | findstr /i "http token secret password cef electron ipc protocol"
rabin2 -i app.exe | findstr /i "CreateProcess ShellExecute WinExec URLDownload memcpy recv"
```

重点看：`CreateProcess*`、`ShellExecute*`、`WinExec`、`URLDownloadToFile`、`WinHttp*`、`InternetOpen*`、`memcpy`、`strcpy`、`HeapAlloc`、`VirtualAlloc`、`RegOpenKey`。

导出 ≠ 可达：`rabin2 -s` 列出的导出符号只是候选，导入侧（`-i`）和 IDA `xrefs_to` 才是“被谁用”的证据；动态断点实际命中才最终确认。只对着导出表硬调的函数不测、不报。

## 3. asar（Electron）

```bat
asar list app.asar
asar extract app.asar out
asar extract-file app.asar package.json
```

看：

- `package.json` 的 `main`、`preload`、`dependencies`。
- `main` 里的 `ipcMain`、`protocol`、`shell.openExternal`、`loadURL`、端口监听。
- preload 里的 `contextBridge.exposeInMainWorld` 暴露面。
- `node_modules` 里的 `node-serialize`、`serialize-javascript`、`eval`、`new Function`。

## 4. curl

```bat
:: 本地端口（<port> 换成目标服务实际监听端口）
curl.exe -sS -i --max-time 5 http://127.0.0.1:<port>/

:: 路径遍历（保留 ..，不要让 curl 规范化）
curl.exe -sS -i --path-as-is http://127.0.0.1:<port>/../../../Windows/win.ini

:: JSON POST
curl.exe -sS -i -X POST -H "Content-Type: application/json" ^
  --data "{\"url\":\"http://127.0.0.1:8080/hit\"}" http://127.0.0.1:<port>/download

:: CDP
curl.exe -sS http://127.0.0.1:9222/json/version
curl.exe -sS http://127.0.0.1:9222/json/list
```

注意：`--path-as-is` 才会保留 `..`；`--max-time` 防止服务挂起；`-i` 看响应头/状态码。

## 5. frida

```bat
frida-ps
frida-ps -a
frida -f app.exe -l hook.js
frida -p <pid> -l hook.js
frida-trace -f app.exe -i CreateProcessW -i ShellExecuteW -i URLDownloadToFileW
```

`hook.js`：

```js
const p = Module.getExportByName
  ? Module.getExportByName(null, 'CreateProcessW')
  : Module.findExportByName(null, 'CreateProcessW');
Interceptor.attach(p, {
  onEnter(args) {
    console.log('CreateProcessW', args[0].readUtf16String());
  }
});
```

常用 hook 点：

- 进程/命令：`CreateProcessW`、`ShellExecuteW`、`WinExec`。
- 网络/下载：`URLDownloadToFileW`、`WinHttpOpenRequest`、`InternetOpenUrlW`、`recv`、`send`。
- 内存/解析：`memcpy`、`memmove`、`HeapAlloc`、`VirtualAlloc`。
- 文件：`CreateFileW`、`ReadFile`、`WriteFile`。
- 协议/注册表：`RegOpenKeyExW`、`RegQueryValueExW`。

JS bridge 方法在渲染进程里，优先用 DevTools/CDP 或页面注入；native 侧用 frida hook 对应导出/虚表。

## 6. cdb

```bat
:: 附加
cdb -p <pid>

:: 启动并下断点
cdb -c "bp kernel32!CreateProcessW; g" app.exe

:: 崩溃 dump
cdb -z out.dmp -c "!analyze -v; q"
```

常用命令：`lm`（模块）、`kv`（栈）、`r`（寄存器）、`!analyze -v`、`.ecxr`、`s -a`、`.dump /ma C:\temp\app.dmp`、`q`。
符号：`.symfix; .reload`。

## 7. procdump

```bat
:: 异常时抓全内存 dump（先确认进程名/PID）
procdump -ma -e 1 -f "" <pid> out.dmp

:: 等进程启动后抓
procdump -ma -w app.exe out.dmp

:: 启动并监控
procdump -ma -x C:\dumps app.exe
```

分析：`cdb -z out.dmp -c "!analyze -v; q"`，或 WinDbg 打开 dump。

## 8. Ghidra

GUI：导入 → Auto Analyze → 看 Symbol Tree / Imports / Strings / Decompiler。

Headless：

```bat
<tools>\ghidra\support\analyzeHeadless.bat ^
  C:\ghidra_proj ClientProj -import target.dll -postScript script.py
```

- 找导入：`CreateProcess`、`ShellExecute`、`URLDownload`、`memcpy`、`recv`。
- 找字符串：URL、协议名、错误提示、白名单、扩展名。
- 交叉引用：从危险 API 回溯到解析/协议入口。
- .NET 程序集 Ghidra 反编译效果有限，优先 dnSpy/ILSpy（若可用）。

## 9. 组合流程

1. **模块梳理先行**：先枚举主进程及各子进程（renderer/gpu/utility）**实际加载的模块清单**，以它定攻击面。OpenArk MCP：`ps_list` → `ps_module_list`（每个目标进程各拉一次，按 name/company/描述过滤出非系统模块）；或 PowerShell `Get-Process <name> | % { $_.Modules }`。安装目录里存在但**未加载**的 DLL 不纳入挖掘；只有确认了动态加载路径（更新、插件、延迟加载）才补进列表。
2. **Recon**：进程/模块/端口/协议/文件类型；OpenArk 或 PowerShell。
2. **Static**：`rabin2` 看导入/字符串 → `asar` 解 Electron → Ghidra/IDA 反编译关键函数。
3. **Dynamic**：frida 追参数/返回值 → cdb/x64dbg 下断 → procdump 抓崩溃。
4. **Network**：curl 打本地端口 → Python 起回环日志 → 确认请求真的到达。
5. **Evidence**：日志、截图、dump、函数/行号、响应；测完清理。

## 10. 注意

- 32/64 位匹配：x32dbg/x64dbg、frida 架构、cdb 位数。
- 符号/PDB：能加载就加载，栈和函数名会清楚很多。
- 反调试/完整性检查：先对比“附加/不附加”的行为差异；只在授权测试环境处理。
- 调试器改变时序/堆布局；多线程/网络解析配日志、ETW、抓包。
- 只在自己的测试环境附加/写内存；不 patch 生产进程。
- PoC 用计算器/回环日志/读 hosts，不做破坏性验证。
