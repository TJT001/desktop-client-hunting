# 客户端内存类漏洞（外部输入 → 原生解析器 / 进程）

> 定位：补“引擎 1day”之外的原生内存安全问题——文件/协议/媒体解析、IPC 反序列化、共享内存。  
> 核心：内存 bug 是 sink；“崩了”只是现象。先证外部输入到达解析器，再证可控的越界/生命周期错误，最后才谈影响。  
> 引擎层（V8/Blink）按版本回溯，见 `cef-trust-boundaries.md` / `electron-trust-boundaries.md`；本文件管客户端自己的原生代码和第三方解析库。

## 0. 一句话

**外部可达 → 自动/点击到达解析器 → 可复现的内存错误 → 可控 primitive → 影响。**  
只有 crash、没有 primitive：按 DoS/未证实处理，不写 RCE。

## 1. 外部输入面（source）

| 类别 | 典型载体 | 外部可控性 | 到达判据 |
|---|---|---|---|
| 文件传输 | IM 文件、群文件、邮件附件、拖拽、剪贴板、文件关联、最近文件 | 任意发文件的人 | 收到即解析 / 预览 / 缩略图 / 索引 |
| 媒体 | 图片、表情、GIF、WebP/AVIF/HEIC、SVG、音频、视频、字幕、字体 | 任意发消息的人 | 自动下载、自动预览、解码器 |
| 文档 | PDF、Office、压缩包、安装包、更新包、电子书 | 任意发文件的人 | 打开/预览/解析器 |
| 网络协议 | 私有 TCP/UDP/HTTP API、WebSocket、P2P、局域网发现、推送 | 对端 / 中间人 / 任意站点 | 登录前解析、自动连接、后台同步 |
| IPC | 命名管道、Unix socket、共享内存、COM/DBus、本地 HTTP | 本机进程；网页（DNS rebinding/CSRF） | 只有本机可达 → 本地能力；跨权限边界按提权 |
| 页面 | 内嵌浏览器的 HTML/CSS/JS/WebGL/WebAudio/WebCodecs | 任意页面 | 进的是客户端引擎（G1） |
| 系统集成 | shell 扩展、右键菜单、预览 handler、协议 handler | 任意文件/链接 | 由资源管理器或客户端自动调用 |

最强的到达是**收到即解析**：缩略图、预览、索引、杀毒扫描、通知、云同步、自动下载。  
需要用户点击/打开的仍然算外部，但报告里要写清交互。

## 2. 闸门（在 G0–G3 上细化）

| 闸门 | 问题 | 不通过时 |
|---|---|---|
| **M0 可达** | 普通互联网攻击者能否把样本送到解析器？ | 只有本机/物理/调试 → 丢弃（跨权限边界的提权除外） |
| **M1 到达** | 自动解析还是点击？在哪个进程？解析前有没有校验/沙箱？ | 只写“潜在/未确认” |
| **M2 primitive** | 是否可复现的 OOB read / OOB write / UAF / 类型混淆？数据、长度、偏移可控吗？ | 只写 crash/DoS，不写 RCE |
| **M3 影响** | 信息泄露 / 代码执行 / 沙箱逃逸？ | 没有 M2 不写 M3 |

## 3. 常见 bug 类型与高发点

| 类型 | 典型成因 | 客户端高发点 |
|---|---|---|
| 堆/栈溢出 | 长度未校验、`memcpy` 用输入长度 | 图片/媒体/文档解析、协议解包 |
| 整数溢出 → 分配过小 | `w * h * bpp`、长度加法/乘法 | 图像解码、压缩包、字体 |
| OOB read | 索引未校验、长度与缓冲区不一致 | 解析器、指纹/版本检测、错误路径 |
| OOB write | 写入长度/偏移可控 | 解码器、序列化、共享内存 |
| UAF / double free | 对象生命周期、错误路径、回调重入 | 异步解析、IPC 回调、UI 线程 |
| 类型混淆 | 联合体/对象类型未校验、C++ 向下转型 | 协议消息、脚本绑定、插件接口 |
| 未初始化内存 | 分配后未清零、错误路径返回 | 信息泄露、密钥/指针泄漏 |
| 反序列化 | 直接信任长度/类型/对象图 | 私有协议、IPC、剪贴板、配置；独立方法见 `deserialization.md` |
| 路径/格式混淆 | 扩展名 vs magic、MIME 嗅探 | 文件路由到错误解析器 |

高发第三方库（先指纹再查 CVE，比盲 fuzz 快）：

- 图像：libwebp、libavif、libjpeg-turbo、libpng、libtiff、OpenEXR、libheif。
- 媒体：FFmpeg、libvpx、libaom、dav1d、GStreamer。
- 文档：PDFium、Poppler、MuPDF、libarchive、minizip、7-Zip、zlib/zstd/brotli。
- 文本/结构：libxml2、expat、JSON/protobuf/flatbuffers、PCRE2/Oniguruma。
- 其他：FreeType/HarfBuzz、librsvg、SQLite、Lua/QuickJS、OpenSSL/ASN.1。

例：libwebp **CVE-2023-4863**（堆溢出，在野利用）就是“图片自动预览/解码”这一类投递的典型形态；先看目标打包的 libwebp 版本，再谈能不能到。

## 4. 怎么找（四条路）

1. **版本 / CVE 回溯**（最快）
   - 指纹：DLL/so/dylib 文件版本、`strings`、`dumpbin /imports`、`ldd`、`otool -L`、SBOM、`package.json`、安装目录里的第三方库。
   - 对照：NVD、GitHub advisories、OSV、厂商公告；确认版本区间与组件是否真的被调用。
2. **补丁 diff / 1day**
   - 拿修复前后两个版本，BinDiff/Ghidra/IDA 对比；找新增的长度/边界检查。
   - 从检查点反推触发条件，构造最小样本；不要直接套公开 PoC，先对版本/位数/配置。
3. **Fuzzing**
   - harness 解析入口，喂真实样本 + 结构变异；AFL++ / libFuzzer / honggfuzz。
   - 有源码：ASan/UBSan/MSan；Windows MSVC 可用 `/fsanitize=address`。
   - 闭源二进制：PageHeap / Application Verifier（`gflags /p /enable <exe> /full`）、WinDbg、x64dbg、Frida/API Monitor。
   - 语料：客户端自己的缓存/临时文件、公开样本集、同格式正常文件；结构感知变异优先。
4. **静态 / 动态审计**
   - 静态：找 `memcpy`/`memmove`/`strcpy` 的用户长度、分配算术、对象生命周期、反序列化入口；IDA/Ghidra + 交叉引用。
   - 动态：x64dbg（用户态 API/内存断点）与 WinDbg（`!analyze -v`、`!heap -p -a`、PageHeap、TTD 回放）；在 `malloc/free`、解析入口、错误路径下断点。

### Windows 工具链：OpenArk + IDA Pro

> 若本机已接 OpenArk MCP / IDA Pro MCP，直接用对应工具；没有就用 GUI/IDA 客户端做同样的事。  
> 两者都只回答“本地发生了什么 / 代码怎么走”，**不替代 G0/G1 的外部可达性判断**。

**OpenArk（运行时 / 系统面）**

| 目标 | 工具（MCP） | 看什么 |
|---|---|---|
| 进程与子进程 | `ps_list`、`ps_detail_list`、`ps_tree` | 主进程、渲染/工具子进程、命令行、父进程 |
| 模块与版本 | `ps_module_list` | 第三方解析库（libwebp/FFmpeg/PDFium/FreeType…）、基址、路径、版本 |
| 句柄 | `ps_handle_list` | 文件、命名管道、Section（共享内存）、事件 —— IPC/共享内存审计入口 |
| 内存 | `mem_regions`、`mem_read`、`mem_search` | 模块基址、堆区、版本字符串、特征串 |
| 线程 | `ps_thread_list`、`ps_thread_stack` | 解析线程、崩溃线程、调用栈 |
| 网络 | `net_port_list`、`net_ps_list` | 本地服务绑定 `127.0.0.1` 还是 `0.0.0.0` |
| 内核/监控 | `kern_*`、`mon_*` | 驱动、回调、过滤、ETW；只在测试 VM、明确需要时用 |

注意：

- **导出 ≠ 可达**：导出表只用于筛候选，必须确认函数**被程序实际调用**（IDA `xrefs_to` 有调用方、调用链能回溯到输入入口，或 x64dbg/frida 断点实际命中）再投入分析；无调用方、只有导出导出的 API 不测不报。
- **模块梳理以实际加载为准**：`ps_module_list` 的输出（主进程 + 每个子进程分别拉）是攻击面依据；安装目录里存在但未加载的 DLL 一律不挖——进程没加载它就不可达。只有确认动态加载路径（更新、插件、延迟加载）才纳入。
- 先只读；`kern_*_op`、`sys_run`、`ps_kill` 等写操作不要在客户环境/生产上用，可能蓝屏或改系统状态。
- OpenArk 看到的是本机运行时，不能证明“互联网攻击者能触发”；找到解析器/句柄后回到 §5 做到达性验证。
- 用快照/VM；测完恢复。

**IDA Pro（静态面）**

| 目标 | 工具（MCP） | 看什么 |
|---|---|---|
| 打开/概览 | `idb_list`、`idb_open`、`survey_binary` | 架构、导入、字符串、段 |
| 输入入口 | `list_funcs`、`func_query`、`search_text` | 文件格式名、MIME、扩展名、错误串 |
| 危险 API | `imports`、`xrefs_to` | `memcpy`/`memmove`/`ReadFile`/`recv`/`HeapAlloc`/`VirtualAlloc` 的调用者 |
| 数据流 | `decompile`、`disasm`、`trace_data_flow` | 长度 → 分配 → 拷贝；边界检查是否缺失 |
| 指纹/diff | `find_bytes`、`find_regex`、`make_signature` | 魔数、版本串；漏洞版 vs 修复版对照 |
| 崩溃回映射 | `decompile`、`xrefs_to` | 崩溃地址/栈 → 伪代码 → 根因 |

流程：

1. `idb_open` 目标 DLL/EXE；`survey_binary` 看导入和字符串。
2. `imports` 找内存/文件/网络 API；`xrefs_to` 回溯到解析入口。
3. `decompile` + `trace_data_flow` 跟“输入长度 → 分配大小 → 拷贝/索引”；重点看整数运算和 `size_t` 截断。
4. 两个版本做 diff（IDA + BinDiff 或人工对照），找新增的边界检查。
5. 崩溃/断点地址回到 IDA 看伪代码；再配 PageHeap/WinDbg/x64dbg 看堆和寄存器。

注意：

- 静态找到“危险调用”不等于可达；必须用样本/协议验证真的能走到（M1）。
- 反编译结果可能被优化/混淆；关键判断回到汇编和动态。
- 只在自己的测试样本/授权目标上分析。

**动态调试：x64dbg + WinDbg**

| 场景 | 工具 | 关键操作 |
|---|---|---|
| 用户态 API/单步 | x32dbg / x64dbg | 附加或启动；`bp CreateFileW`、`bp ReadFile`、`bp recv`、`bp memcpy`、`bp HeapAlloc`；看调用栈/参数/dump |
| 目标缓冲区 | x64dbg | 内存断点/硬件断点盯读写；`traceinto` / `traceover` 跟解析循环 |
| 崩溃现场 | WinDbg | 附加或打开 dump；`!analyze -v`、`.ecxr`、`kv`、`r`；`!heap -p -a <addr>` |
| 堆越界 | WinDbg + PageHeap | `gflags /p /enable <exe> /full` 后复现；`!heap -p -a` 看分配/释放栈 |
| 时间回溯 | WinDbg TTD | 录制后 `g-` / `g+` 回放，查看崩溃前的堆、寄存器和分支 |
| 反调试 | x64dbg | ScyllaHide 等插件（仅授权测试）；或换 WinDbg/内核调试 |
| 子进程 | 两者 | 附加到解析子进程 PID；WinDbg `.childdbg 1`；x64dbg 手动附加对应 PID |
| 符号 | 两者 | `_NT_SYMBOL_PATH` 指向 Microsoft symbol server；加载目标 PDB |

流程：

1. OpenArk 先确认进程、模块（以 `ps_module_list` 实际加载结果为准，不按安装目录文件猜）、位数、解析线程。
2. x64dbg 附加/启动；在文件、网络、内存 API 下断，记录每次调用的长度、指针、调用栈。
3. 喂样本；用内存断点盯目标缓冲区，确认越界读/写发生在哪一行。
4. 崩溃后：WinDbg `!analyze -v` 看异常类型（读/写）、faulting address、寄存器；PageHeap 复现拿分配栈。
5. 地址回 IDA：按运行时基址 rebase，或直接在 IDA 里按 RVA 定位；对照伪代码确认长度/边界检查。
6. 记录：断点、栈、寄存器、堆块、样本 hash、客户端版本。

注意：

- x64dbg 是用户态；驱动/内核回调/SSDT 这类用 WinDbg 双机调试。
- 反调试/完整性检查可能让进程退出或走不同分支；先对比“附加/不附加”的行为差异。
- PageHeap 改变堆布局，适合发现，不适合直接当利用环境。
- 调试器改变时序；多线程/网络解析要配日志、ETW、抓包。
- 32/64 位要匹配；ASLR 下先 rebase 再对照 IDA。
- 只在自己的测试环境附加/写内存；不要 patch 生产进程。

## 5. 到达性验证（客户端特有）

- **自动触发**：收到文件就生成缩略图/预览/索引/扫描 → 最强；记录触发时间与进程。
- **进程归属**：主进程/浏览器进程（通常无沙箱）> 工具进程/服务（可能高权限）> 渲染进程（有沙箱）。同一 bug 在不同进程影响不同。
- **解析前校验**：扩展名、magic、大小、签名、白名单；能否用双扩展名/MIME 混淆路由到别的解析器。
- **登录前/后**：协议解析在认证前可达，价值更高。
- **临时文件**：样本落盘路径、权限、是否被其他进程再次解析。
- **网络位置**：只有中间人/同 LAN 可达 → 按网络位置降级，不算普通互联网投递。

## 6. 崩溃 → 可利用性 triage

1. 同版本、同 OS、同配置复现；记录样本 hash、客户端版本、解析库版本。
2. 看 faulting instruction 与寄存器：读还是写？地址/长度/偏移是否来自样本？
3. 分类：
   - **OOB read**：可能信息泄露（ASLR 指针、凭证、内存内容）；看泄露数据能否回到攻击者。
   - **OOB write**：可能 RCE；看写入值/地址/长度是否可控。
   - **UAF**：看释放后能否复用、复用对象是否含函数指针/长度。
   - **类型混淆**：看对象布局/vtable 是否可控。
   - **整数溢出**：回溯分配大小算术，确认是否导致过小分配。
4. 记录缓解：ASLR、DEP/NX、CFG、CET、stack cookie、沙箱、32/64 位、分配器（LFH/Segment Heap）。
5. 证明 primitive：
   - 信息泄露：展示泄露的字节（脱敏），说明能绕过什么。
   - 写/执行：在隔离环境做最小无害验证（本机弹计算器即可），不做持久化。
6. 只有 crash：写“内存破坏崩溃，可利用性未证实”，不要写 RCE。

## 7. 报告口径

- 标题：**source → delivery（自动/点击）→ 解析器/进程 → primitive → 影响**。
- 必带：客户端版本、OS/build、样本 hash 或最小复现、解析库版本、崩溃栈、faulting instruction、缓解状态。
- 定级：
  - 只崩 / DoS：低，不写高危。
- 本地提权：只有跨权限边界（标准用户→管理员/SYSTEM、沙箱→宿主、渲染进程→主进程）才报；同用户本地代码执行不报。
  - OOB read 有实际泄露：中到高，看泄露内容。
  - OOB write / UAF / 类型混淆且可控：高到严重。
  - 跨沙箱/到主进程：再加一档。
- 明确写“已证实 primitive / 仅崩溃未证实”；不要把 fuzzer  crash 直接当 RCE。
- 样本和票据脱敏；恶意样本走程序规定的加密渠道，不贴公开报告。

## 8. 纪律

- 样本在 VM/快照里跑；不在宿主机直接执行不可信文件。
- 本地崩溃/本地代码执行：同用户不按提权报；只有跨权限边界才报。
- 只用自己的测试账号/私有环境；不要把恶意样本发给真实用户或公开群。
- 测完清理临时文件、崩溃转储、调试器附加；不留持久化。
- 其余红线：只对授权目标；不制造真资损、不破坏数据、不公开样本；测完恢复环境。

## 9. 快速清单

- [ ] 外部输入能到解析器吗？自动还是点击？
- [ ] 哪个进程解析？有没有沙箱/权限？
- [ ] 解析库/版本能指纹吗？有对应 CVE 吗？
- [ ] 崩溃是 OOB read / OOB write / UAF / 类型混淆？
- [ ] 数据、长度、偏移可控吗？
- [ ] ASLR/DEP/CFG/CET/沙箱状态如何？
- [ ] 只崩，还是能证明 info leak / RCE？
- [ ] 报告是否区分“崩溃”与“可利用”？
