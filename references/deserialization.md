# 客户端反序列化攻击面

> 定位：客户端里“外部数据 → 类型化对象”的边界。它和内存类漏洞并列，不是子类：反序列化常常不需要内存破坏就能到 RCE。  
> 核心：先证外部数据到达反序列化器，再证类型/对象图可控，最后才谈 gadget 与影响。

## 0. 一句话

**外部可达 → 到达反序列化器 → 类型/对象图可控 → gadget → 影响。**  
只有“用了 BinaryFormatter/pickle”不是漏洞；要有 source 和 gadget。

## 1. 为什么客户端是高发面

- 富运行时：.NET / Java / Python / Node / PHP / Ruby 都自带或常用类型化序列化。
- 跨边界：渲染进程 → 主进程、网页 → 原生桥、文件 → 解析器、插件 → 宿主。
- 高权限：主进程/服务通常无沙箱，反序列化直接在特权进程执行。
- 投递容易：发文件、发消息、剪贴板、导入/备份、更新包、插件包。
- Web→native：渲染进程 XSS 后可把序列化数据送进主进程反序列化器。

## 2. 输入面（source）

| 输入面 | 载体 | 谁可控 | 到达判据 |
|---|---|---|---|
| 文件/导入 | 项目文件、配置、备份、导出包、聊天文件、邮件附件 | 任意发文件的人 | 打开/导入/自动解析 |
| 剪贴板/拖放 | 自定义格式、OLE/COM 对象、文本 | 任意网页/任意人 | 粘贴/拖入即解析 |
| IPC | 渲染进程 → 主进程、WebView/CEF 桥、命名管道、本地 HTTP | 页面/本机进程（跨权限边界按提权） | 主进程反序列化 |
| 网络 | 私有协议、RPC、WebSocket、gRPC、RMI/JMX、.NET Remoting | 对端/中间人 | 登录前/自动连接 |
| 插件/扩展 | 插件包、配置、插件 RPC | 插件作者/市场 | 安装/加载/调用 |
| 更新/同步 | 更新清单、云同步、配置下发 | 更新服务器/运营 | 自动同步 |

## 3. 各运行时的危险入口

| 运行时 | 危险 API / 格式 | 备注 |
|---|---|---|
| .NET | `BinaryFormatter`、`NetDataContractSerializer`、`LosFormatter`、`ObjectStateFormatter`、`SoapFormatter` | 新 .NET 默认禁用/移除，老 Framework 仍常见 |
| .NET | Json.NET `TypeNameHandling` != `None`；`JavaScriptSerializer` + `SimpleTypeResolver` | 类型名可控就有戏 |
| .NET | `XamlReader.Parse/Load`、`Type.GetType` + `Activator.CreateInstance` | XAML 的 `ObjectDataProvider` 是常见 gadget |
| .NET | `DataContractSerializer` + `DataContractResolver`；MessagePack `Typeless` | 类型解析/联合类型 |
| Java | `ObjectInputStream.readObject`、RMI/JMX、Hessian、Kryo | 经典 gadget 链 |
| Java | Jackson `activateDefaultTyping`；Fastjson `autoType`；XStream；SnakeYAML `Constructor` | 多态反序列化 |
| Python | `pickle`/`cPickle`/`dill`/`joblib`/`shelve`、`yaml.load`（非 SafeLoader）、`jsonpickle`、`marshal` | `__reduce__` 直接执行 |
| PHP | `unserialize`、`phar://`、session 反序列化 | `__wakeup`/`__destruct` gadget |
| Ruby | `Marshal.load`、`YAML.unsafe_load`、`Oj` object mode | 版本相关 |
| Node/Electron | `node-serialize`、`eval`/`new Function`/`vm`、`require` 不可信路径、JSON 原型污染 | `vm` 不是安全边界 |
| 原生 | Boost.Serialization、Cereal、QDataStream/QVariant、COM `IPersistStream`/OLE | 类型混淆/UAF，见 `memory-safety.md` |

## 4. 格式识别

| 格式 | 特征 |
|---|---|
| Java 序列化 | `AC ED 00 05`；base64 `rO0AB` |
| .NET BinaryFormatter | `00 01 00 00 00 FF FF FF FF` |
| .NET ViewState | base64，`__VIEWSTATE` |
| PHP | `O:`、`a:`、`s:`、`i:` |
| Python pickle | `80 04 95` / `80 05 95`；base64 `gASV` |
| Ruby Marshal | `04 08` |
| YAML | `---`、`!!`、`!ruby/object`、`!!python/object` |
| JSON 多态 | `$type`、`@type`、`__type`、`type` + 类名 |
| XAML | `<` + `ObjectDataProvider`、`Assembly=` |
| protobuf/flatbuffers | 二进制；按 schema 解析，通常无类型名 |

## 5. 闸门

| 闸门 | 问题 | 不通过时 |
|---|---|---|
| **D0 可达** | 攻击者能把序列化数据送到客户端吗？ | 只有本机/调试 → 丢弃（跨权限边界的提权除外） |
| **D1 到达** | 客户端会反序列化吗？自动还是点击？哪个进程？ | 只写“潜在” |
| **D2 类型可控** | 类名/类型标签/对象图可控吗？有 binder/白名单吗？ | 只写“反序列化 sink” |
| **D3 gadget/影响** | 有可用 gadget 吗？RCE/文件/认证绕过？ | 没有 D2/D3 不写 RCE |

## 6. 找 gadget 与验证

1. 确认运行时/库版本：加载的程序集、jar、`node_modules`、Python 包、DLL 版本。
2. 找反序列化入口：文件打开、剪贴板、IPC handler、网络 recv、插件加载。
3. 看类型控制：`SerializationBinder`、`TypeNameHandling`、`autoType`、allowlist、`allowed_classes`。
4. 找 gadget：**进程实际已加载**的程序集/类路径里的已知链（OpenArk `ps_module_list` / 已加载 jar、程序集清单确认），静态盘上存在但没加载的不算可达；先做无害副作用（DNS/HTTP 回调、写临时文件、弹计算器）。
5. 最小 PoC：只证明一条链；不删数据、不持久化、不外联真实资产。
6. 报告：写清“到达反序列化器”和“gadget 已证实”是两件事。

## 7. 影响与报告

- RCE：反序列化 gadget 直接执行命令 → 高/严重。
- 文件读写/凭证：反序列化触发文件操作/读取 → 高。
- 认证绕过/逻辑：类型混淆绕过校验 → 中/高。
- 只崩/DoS：低，不写高危。
- 本地提权：只有跨权限边界（低权限→高权限/沙箱→宿主/渲染进程→主进程）才报；同用户不报。
- 标题：**source → delivery → deserializer → gadget → impact**。
- 未证 gadget：写“反序列化入口可达，影响未证实”，不写 RCE。

## 8. 审计/防守清单

- 不可信数据不用原生序列化；用 JSON + 严格 schema，或 protobuf 生成代码。
- .NET：禁 `BinaryFormatter`/`NetDataContractSerializer`/`LosFormatter`/`SoapFormatter`；`TypeNameHandling.None`；binder 白名单；不可信输入不进 `XamlReader`。
- Java：避免 `ObjectInputStream`；用 `ObjectInputFilter`；关 Jackson default typing；Fastjson safeMode；XStream allowlist。
- Python：不可信数据不用 `pickle`；`yaml.safe_load`；只用 `json`。
- PHP：`unserialize` 加 `allowed_classes`；避免 `phar://`。
- Ruby：不用 `Marshal.load`；`YAML.safe_load`。
- Node：不可信数据不 `eval`/`new Function`/`vm`；不用 `node-serialize`；校验 JSON schema；IPC 用结构化克隆。
- 原生：版本化 schema、长度限制、类型标签校验、不要直接信任指针/vtable。

## 9. 与内存类的关系

- 反序列化可以**不经过内存破坏**直接 RCE（gadget 链）；它是独立攻击面，不是内存类的子类。
- 原生序列化器（Boost/Cereal/QDataStream/COM）也可能产生类型混淆/UAF/OOB；那部分按 `memory-safety.md` 做 primitive triage。
- 两者共用同一条纪律：先证外部到达，再证可控，最后谈影响。

## 10. 快速清单

- [ ] 外部数据能到反序列化器吗？自动还是点击？
- [ ] 哪个进程反序列化？有沙箱吗？
- [ ] 格式是什么？运行时/库版本？
- [ ] 类型名/对象图可控吗？有 binder/白名单吗？
- [ ] 有可用 gadget 吗？
- [ ] 只证到入口，还是证到 RCE/文件/认证绕过？
- [ ] 报告是否区分“可达”与“gadget 已证实”？
