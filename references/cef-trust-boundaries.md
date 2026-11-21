# CEF 信任边界审计（引擎 / 框架 / 绑定 / 配置）

> 适用：CEF、CefSharp、CefSharp.Wpf、CefSharp.WinForms、自研 CEF 封装。  
> 核心：渲染进程里的网页内容不可信。所有跨到浏览器进程、本地文件、OS 的路径都要设防。  
> CVE 条目于 2026-10-22 用 NVD API 核对；版本/分值以 NVD 为准，利用前仍要核对目标实际版本。

## 0. 四层信任边界

| 层 | 不可信 → 可信 | 典型入口 | 审计点 | 对应闸门 |
|---|---|---|---|---|
| **引擎** | 网页 → V8 / Blink | 任意被 CEF 加载的页面 | 版本、位数、沙箱、1day 适配 | G1 / G2（sink） |
| **框架** | 渲染进程 → 浏览器进程 | `CefProcessMessage`、共享内存、资源加载回调 | 尺寸、类型、边界、句柄、来源 | G2 |
| **绑定** | URL / JS → 本地资源 / 原生方法 | `CefSchemeHandlerFactory`、JS 对象、`EvaluateScriptAsync` | 规范化、目录边界、白名单、参数校验 | G0 / G1 |
| **配置** | 外部输入 → OS / 调试接口 | `OnProtocolExecution`、DevTools、启动参数 | scheme/host 白名单、绑定地址、生产开关 | G0 |

数量最多的是引擎层；但**能不能算外部漏洞，取决于投递和配置**。引擎层是 sink，先证投递。

## 1. 引擎层（网页 → V8 / Blink）

CEF 内嵌的 Blink/V8 继承的是 **Chromium 的整个漏洞历史**：UAF、堆溢出、类型混淆、解析器越界。下面的 CVE 只是示例，**不是清单**；真正要查的是“目标 CEF 的 Chromium 基线之后，所有已修复的 Chrome 安全漏洞”，再按组件、构建和投递过滤。

### 1.1 先算 Chromium 基线

- 源码/头文件：`include/cef_version.h` 的 `CEF_VERSION` 直接带 `chromium-x.y.z.w`。
- 版本号：CEF 的 major 通常等于 Chromium major；CefSharp 的 major 也通常对到 CEF/Chromium major（如 `148.0.90` → Chromium 148 线）。
- 没有源码：看 `libcef.dll` 文件版本、安装目录里的 `cef_version.h`、UA、能开 DevTools 时的 `chrome://version`。
- 基线之后的 Chrome 安全修复都算候选；CEF 通常不做安全 backport，靠升级 Chromium 基线。

### 1.2 枚举候选

| 来源 | 用法 |
|---|---|
| Chrome Releases | `chromereleases.googleblog.com` 的 Stable Channel Update，按版本列 CVE |
| NVD API | `keywordSearch=Chrome` / `Chromium`；或 CPE `cpe:2.3:a:google:chrome`；注意 120 天窗口与限流 |
| NVD 条目 | 描述里的 “prior to x.y.z” 与目标版本直接比较 |
| CEF builds / release notes | 确认 CEF 基线版本；Spotify CEF builds 索引 |
| 组件公告 | V8 / Blink / Skia / PDFium / ANGLE / FFmpeg 的独立修复 |

### 1.3 过滤

1. **组件在不在**：V8、Blink、WebGL/ANGLE、WebAudio、WebCodecs、PDFium、Skia、媒体解析、Mojo。Chrome UI、扩展、同步、更新器、企业策略这些 CEF 里通常没有（有扩展支持的版本要单独确认）。
2. **构建开没开**：32/64 位、JIT、沙箱、OSR、feature flags、GPU 加速。
3. **能不能投递**：攻击者页面是否真的被这个 CEF 加载；只走系统浏览器不算。
4. **能不能利用**：公开 PoC / 在野、目标版本、缓解措施（ASLR/CFG/CET）、沙箱。

### 1.4 快速查询

```bash
# NVD：关键词 + 120 天窗口（无 API key 时限流更严）
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Chrome&pubStartDate=2025-01-01T00:00:00.000&pubEndDate=2025-04-30T23:59:59.999"
```

Chrome Releases 的版本列表通常比 NVD 更全、更早；NVD 用来补影响版本与分值。NVD 的 CPE 配置可能滞后，最终以 Chrome Releases + 目标实际版本为准。

### 1.5 示例（不是清单）

| CVE | 组件 | 影响版本 | 类型 | NVD | 备注 |
|---|---|---|---|---|---|
| CVE-2025-8010 | V8 | Chrome < 138.0.7204.168 | 类型混淆 | 8.8 High | 构造页面触发堆破坏 |
| CVE-2025-8011 | V8 | Chrome < 138.0.7204.168 | 类型混淆 | 8.8 High | 同上 |
| CVE-2024-7971 | V8 | Chrome < 128.0.6613.84 | 类型混淆 | 8.8 / 9.6 | 已在野利用；版本/位数要适配 |

审计要点：

- 不要只查本文示例；按 §1.1–1.3 回溯目标基线之后的**全部** Chrome 修复。
- 取实际版本：`libcef.dll` 文件版本、UA、能开 DevTools 时的 `chrome://version`；CEF 版本号通常能对到 Chromium 大版本。
- 记录 32/64 位、V8 版本、沙箱开关；32 位公开 PoC 不能直接套 64 位。
- CEF 常滞后于 Chromium 安全版本；应用长期不更新 = 长期暴露在已知 1day 下。
- **先有投递再谈 1day**：攻击者页面必须真的被这个客户端的 CEF 加载；只走系统浏览器不算。
- 渲染进程崩溃 ≠ 代码执行；不要把 crash 写成 RCE。

## 2. 框架层（渲染进程 → 浏览器进程）

CEF 用 IPC 和共享内存在进程间传数据。渲染进程可能被恶意网页控制，所以浏览器进程侧的回调必须把数据当不可信输入。

重点接口：

| 接口 | 风险 | 必查 |
|---|---|---|
| `CefProcessMessage` / `OnProcessMessageReceived` | 渲染进程发来的消息被直接使用 | 消息名白名单、参数个数/类型/长度、来源 frame |
| 共享内存（`CefSharedMemoryRegion`、`OnAllocatedSharedMemory`） | 尺寸/内容未校验 → 越界读写 | 实际大小 vs 声明大小、偏移、边界 |
| `CefResourceRequestHandler` / `CefSchemeHandlerFactory` | URL → 本地资源映射 | 路径规范化、目录边界、MIME |
| `CefV8Handler::Execute` / `CefMessageRouter` | JS 参数进入原生逻辑 | 参数类型/长度；返回值不要拼进 JS |
| `OnBeforeBrowse` / `OnBeforePopup` | 任意导航/弹窗 | scheme/域名白名单 |

### CVE-2024-21639（共享内存越界读）

- 位置：`CefLayeredWindowUpdaterOSR::OnAllocatedSharedMemory`。
- 问题：未检查共享内存大小，导致越界读；渲染进程可触发，读发生在**沙箱外的浏览器进程**。
- 影响面：**OSR（离屏渲染）/ layered window updater 路径**；不用 OSR 的应用不在这条路径上。
- 补丁：commit `1f55d2e`；NVD 分值同时有 5.3 与 9.6（不同 metric），按实际影响面取。
- 审计：找到共享内存创建/映射点，核对“声明尺寸、实际尺寸、读取偏移”三者；任何来自渲染进程的长度都要重新校验。

## 3. 绑定层（URL / JS → 本地资源 / 原生方法）

封装库把 C#/托管代码和原生 C++ 接起来，边界上最容易出“翻译错误”。

### CVE-2026-48796（CefSharp 路径遍历）

- 影响：CefSharp **< 148.0.90**；`CefSharp/SchemeHandler/FolderSchemeHandlerFactory.cs`。
- 问题：用 `filePath.StartsWith(rootFolder, StringComparison.OrdinalIgnoreCase)` 判断是否在根目录内，只做字符串前缀匹配，没有强制目录边界。
- 利用：`..%2fwww2/secret.txt` 这类 URL 可以从 `www` 逃到共享前缀的兄弟目录 `www2`，读取本不应暴露的本地文件。
- 正确校验顺序：
  1. URL 解码一次，拒绝二次编码歧义；
  2. `Path.GetFullPath` 规范化，处理 `..`、`.`、分隔符；
  3. 边界判断用 `root + Path.DirectorySeparatorChar` 前缀，或 `Path.GetRelativePath` 结果不以 `..` 开头；
  4. 解析符号链接/ junction 后再判一次（防 realpath 逃逸）；
  5. 只允许白名单扩展名/MIME。
- 审计：所有 `CefSchemeHandlerFactory`、`IResourceHandler`、虚拟主机到目录的映射，逐个看是否只做 `StartsWith`。

### JS 绑定

- CefSharp：`JavascriptObjectRepository.Register/BindObjectAsync` 暴露的方法，参数全部视为不可信。
- 原生：`CefV8Handler`、`CefMessageRouter` 的回调。
- 禁止把参数拼进 `EvaluateScriptAsync` / `runJavaScript` / `eval`；必须用参数化或 JSON 序列化 + 转义。
- 方法本身要有权限分级：只读方法（版本、uid）与危险方法（文件、进程、下载）分开暴露。

## 4. 配置层（外部输入 → OS / 调试）

### OnProtocolExecution

- CEF 的 `OnProtocolExecution(browser, url, allow_os_execution)` 把未知协议交给 OS 处理；返回 `true` 等价于放行。
- 官方文档带 SECURITY WARNING：必须基于 scheme / host / URL 分析决定是否允许，不能无条件放行。
- 审计：是否只允许自家 scheme；是否拦 `file:`、`smb:`/UNC、`javascript:`、`data:`；是否校验 host；`allow_os_execution` 是否被硬编码为 true。
- 风险形态：拉起本机程序、UNC 路径触发 NTLM 泄露、把危险 scheme 交给系统默认处理器。

### 远程调试端口

- 默认 `--remote-debugging-port=9222` 只绑 `127.0.0.1`；DevTools 还有 Host 头校验，较新 Chromium 的 WebSocket 还要 Origin 白名单（常需 `--remote-allow-origins`）。
- 所以：**默认配置下它是本地能力，不是普通互联网投递**。只有绑 `0.0.0.0`、端口被转发/暴露、或本机其他进程/用户可达时，才升级为外部或本地权限问题。
- 例外：若能从低权限上下文跨到高权限（沙箱渲染进程→浏览器进程、普通用户→管理员/SYSTEM），按本地提权上报；同用户可达不报。
- CEF 的 CDP 能执行页面 JS；是否进一步到 OS 命令，取决于页面里有没有强桥。Electron 主进程 `--inspect` 才更接近直接 RCE。
- 报告口径：本地调试端口放“附注/不纳入外部评级”；跨权限边界按主文件 §9.1 单独报。

### 放大项（不是漏洞本身）

- `--no-sandbox`：渲染进程被攻破后少一层隔离。
- `--disable-web-security`：SOP 关闭，页面可读跨域数据。
- `--ignore-certificate-errors`：中间人条件下更容易。
- 这些写在“影响条件”里，不单独定级。

## 5. 审计顺序

1. **认版本**：CEF/Chromium、CefSharp、32/64 位、沙箱。
2. **找跨进程入口**：`CefProcessMessage`、共享内存、资源回调。
3. **找 URL → 本地资源映射**：scheme handler、virtual host、folder mapping。
4. **找协议/调试开关**：`OnProtocolExecution`、`--remote-debugging-port`、`--no-sandbox`。
5. **回到 G0–G3**：谁是互联网可控输入？进的是不是 CEF？能到什么能力？

## 6. 一句话

CEF 的风险集中在四个跨越点：**网页 → 引擎、渲染 → 浏览器、URL → 本地资源、输入 → OS/调试**。  
引擎层不是固定清单，是“目标 Chromium 基线之后的所有安全修复”；框架/绑定层靠校验，配置层靠白名单和生产开关。
