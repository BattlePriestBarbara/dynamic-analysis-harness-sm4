# 脱敏规则说明（SANITIZATION）

本目录下所有报告在**生成阶段**即完成脱敏，而不是事后手工替换。
本文说明：脱了哪些、怎么脱、如何自证"没有漏"，以及如何进一步收紧。

---

## 1. 为什么要单独写一份规则

一份能提交到公共 Git 的逆向报告，最大风险不是技术内容，而是**身份信息**：

- **目标软件身份** —— 应用名、包名、自有域名、深链 scheme、签名证书主体/指纹。
  任意一项都足以让人把样本对回具体产品（进而对回具体厂商与具体版本）。
- **分析者身份与环境** —— 主机路径、用户名、模拟器安装目录、工具链路径。
  这些既是隐私，也会泄露内部目录结构。
- **可直接复用的凭据材料** —— 从样本中提取的对称密钥、签名证书摘要。

因此本仓库采用**双向保证**：

1. 生成时按固定映射表替换（`tools/scrub-map.psd1`）；
2. 提交前跑 `tools/check-sanitization.ps1`，任何遗留命中都会让检查失败。

---

## 2. 路径占位符

| 占位符 | 含义 |
|---|---|
| `<WORK>` | 本地工作根目录（样本、脚本、产物都在其下） |
| `<SAMPLE>` | 样本解包目录（`<WORK>/sample`） |
| `<OUT>` | 产物目录（`<WORK>/out`） |
| `<HOME>` | 用户主目录 |
| `<TOOLS>` | 逆向工具链根目录（Ghidra / unidbg / REA 等） |
| `<UNIDBG>` | unidbg 源码与构建目录 |
| `<GHIDRA_PROJ>` | Ghidra 工程库目录 |
| `<FRIDA>` | frida / frida-server 分发目录 |
| `<EMU>` | Android 模拟器安装目录 |
| `<PY>` / `<JDK>` | Python 解释器目录 / Java 运行环境目录 |
| `<user>` | 主机用户名 |

> 报告正文里出现的所有绝对路径都已替换为上述占位符；复现时按自己的布局替换即可。

## 3. 目标软件身份的替换

| 项 | 内部形态（不出库） | 公开写法 |
|---|---|---|
| 应用名 | 「银行名 + 手机银行」 | **MB 客户端**（Mobile Banking） |
| 厂商前缀 | 3–4 字母银行缩写 | `<vendor>` |
| 包名 | 三段式，含银行缩写 | `com.<vendor>.mobilebank.per` |
| 版本 | 主.次.修订 + versionCode | `v15.x`（精确小版本与 versionCode 已隐去） |
| 自有域名 | 9 个真实主机名 | `*.<vendor>.com.cn`，逐个保留功能角色（CDN / LB / 数据 / H5 / mPaaS） |
| 深链 scheme | 3 个真实 scheme | `bankapp://`、`bankappgt://`、`bankappunion://` |
| 签名证书主体 | CN / OU / O 的真实值 | `CN=<redacted>, OU=<redacted>, …` |
| 证书 SHA-256 | 完整 32 字节 | `<REDACTED-CERT-SHA256>`，保留算法与密钥位数 |
| 含厂商缩写的库名 / JAR | 3 个真实文件名 | `libPassGuard.so`、`libGMEncrypt.so`、`FTBank.jar` |
| PA 沙箱标识 | 含银行缩写的 paId 与 AIDL 接口名 | `com.<vendor>.sandbox.secure.pa`、`ISecureInterface` |
| AIDL 证书钉扎值 | 64 hex | 保留前 8 位 + `…` |

**为什么要连证书指纹一起脱敏**：指纹是最好用的"对号入座"键——拿到它就能在任意
样本库里反查同一应用的所有版本。报告中保留"算法 = SHA1withRSA、密钥 = 1024 bit、
有效期 2010→2065"这些**结构性判断**，足以支撑安全结论，但无法用于指认样本。

---

## 4. 分析者环境

| 项 | 处理 |
|---|---|
| 绝对路径 | 全部 → 占位符（见 §2） |
| 用户名 / 主机名 | `<user>` / 不出现 |
| 模拟器实例名与机型伪装 | 只保留"Android 9 / SDK 28 / x86_64 + arm64 翻译层"这类**能力描述** |
| 工具安装方式（目录联接、硬编码路径） | 保留"为什么这么装"的工程结论，路径用占位符 |
| 内部项目名（旧工程目录） | 泛化为 `<TOOLS>` |

---

## 5. 凭据与密钥材料

| 材料 | 处理 | 理由 |
|---|---|---|
| 样本内提取的对称密钥（16 B） | 仅保留前 8 hex，其余 `*` | 属可复用的密码学材料；报告只需证明"拿到了、是 16 字节、是真 SM4 key" |
| 派生的轮密钥、明文块 | 只保留**摘要与前缀**（如 `0f88581b33aac179…`） | 足以复核比对结论，不构成明文泄露 |
| 文件 SHA-256 | **前 16 hex + `…`** | 与项目既定习惯一致；可防误版本，又不易被搜索引擎反查 |
| 证书 / 签名块 | 不落原文，只记录长度与 sha1 前缀 | — |

> 例外：`classes.dex`、`libexec.so` 等**结构性常量**（大小、偏移、`DT_HASH` 计数）
> 全部保留原值——它们是复现所必需，且本身不指向具体产品。

---

## 6. 刻意**保留**的内容（以及理由）

| 保留项 | 理由 |
|---|---|
| 加固/风控厂商名（iJiami、Bangcle Everisk） | 公开商业产品；报告的核心结论是"这套组合保护的可拆解边界"，去掉厂商名结论就无法被复核 |
| 第三方 SDK 名（UnionPay、FinClip、mPaaS、Realm、SQLCipher、讯飞…） | 同上，且均为公开组件 |
| 具体技术数字（偏移、`nbucket`、块数、字节差分） | 复现所需，且不含身份信息 |
| 结论的**否定形式**（哪些解释被证伪） | 这是报告最有价值的部分，必须原样保留 |

规则表分两层，**真实值不进库**：

| 层 | 文件 | 是否入库 | 内容 |
|---|---|---|---|
| 公开层 | `tools/scrub-map.psd1` | 是 | 只描述**形态**：绝对路径、16 字节密钥、40/64 位摘要、包名 / 域名 / scheme / 证书主体 |
| 本地层 | `tools/scrub-map.local.psd1` | **否**（`.gitignore` 拦截） | **真实值**：厂商缩写、应用名、域名、库名、主机用户名 |

公开层本身不含任何可用于指认样本的信息——这正是它能进库的原因。模板见
`tools/scrub-map.local.example.psd1`（只含占位符，可入库）。

若提交环境更严格，只往本地层的 `ForbiddenLiterals` 加词即可，
`check-sanitization.ps1` 会自动按新映射校验，**不需要改脚本**。

---

## 7. 自证：怎么确认没有漏

```powershell
# 在仓库根目录执行；任何 Error 级命中都会以非零退出码失败
powershell -NoProfile -ExecutionPolicy Bypass -File tools/check-sanitization.ps1

# PowerShell 7 亦可：pwsh -File tools/check-sanitization.ps1

# 只看命中而不失败（排查用）
powershell -NoProfile -ExecutionPolicy Bypass -File tools/check-sanitization.ps1 -Report

# 打印规则表（公开层 + 本地层）
powershell -NoProfile -ExecutionPolicy Bypass -File tools/check-sanitization.ps1 -ListRules
```

检查分三类：

1. **形态**：`PathDriveLetter`（`<盘符>:\` 与 `<盘符>:/`）、`PathUncShare`、`PathUserProfile`、
   `CertSubject`（`CN` 取值必须是 `<redacted>` 形式）、`DomainCn`、`SchemeOpaque`（未登记 scheme）、
   `PackageId`（公开 SDK 包名在白名单内）。
2. **凭据**：`Key16Bytes`（连续 32 hex）、`HexRunLong`（≥33 hex，含"56 位一串"这类长材料）、
   `DigestSha1` / `DigestSha256`、`KeyAssigned`、`HexRunMedium`（警示级）。
3. **PII 与残留**：`EmailAddress`、`MobileNumber`、`Ipv4Address`（回环地址豁免）、`LongBase64`。

三类必须全部为 0 命中，检查才通过。退出码：`0` 通过 / `1` 有 Error 命中 /
`2` 规则或参数问题（规则表缺失、正则写坏、字面量短于 2 字符）。

**局限（必须知道）**：脚本只能证明"没有出现被规则描述的形态"。若本地层缺失，
真实厂商缩写这类**纯字面量**无从比对——此时报告开头会打印
"身份字面量检查已跳过"。所以"能提交"的完整条件是：**本地层在位 + 0 命中**。

**自测（确认规则不是空转）**：在库外造一个含 `<盘符>:\Users\<用户名>\…`、32 位 hex、真实域名、
未登记 scheme 的临时文件，用 `-Path <临时文件>` 跑一遍，应看到四类规则同时命中。
本仓库交付前已做过该负向测试（6 Error / 2 Warn）。

---

## 8. 已知取舍（诚实记录）

1. **版本号被模糊化**，因此"用同版本样本复现"需要自行确认版本，报告给出的是
   `v15.x` + 结构性指纹（5,161 条目 / 289,847,817 B / 单一 ABI）。
2. **域名被掩码**，域名收割的数量级（99 个主机、自有 9 个）保留，具体主机名不可见。
3. **哈希截断到 16 hex**，抗碰撞强度下降，但用于"版本对不对"足够。
4. 本目录**不含任何样本二进制**；`git log` 中也不会出现（`.gitignore` 为白名单模式）。
5. **脚本必须存为 UTF-8 带 BOM**。Windows PowerShell 5.1 会把无 BOM 的 UTF-8 当作 ANSI(GBK)
   读取——中文正则与提示会变成乱码，甚至直接解析失败。改完 `tools/*.ps1` 请确认首三字节是
   `EF BB BF`（`Format-Hex -Path <文件> -Count 3`）。
6. **公开 SDK 白名单会随报告引用而变化**。`scrub-map.psd1` 里 `Allow.Packages` 与
   `PackageId.Allow` 是两处重复清单，新增公开 SDK 时**必须同时改**，否则文档里合法的
   第三方包名会被判成泄露。

