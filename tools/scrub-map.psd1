<#
    scrub-map.psd1 —— 脱敏规则表（可入库版本）

    设计约束：本文件会进入 git，因此 **只能写"形态"，不能写"真实值"**。
      · 公开层 = 本文件：绝对路径、16 字节密钥、40/64 位摘要、证书主体、
        包名/域名/scheme 的**通用形态**。这些规则本身不泄露目标身份。
      · 本地层 = scrub-map.local.psd1（已被 .gitignore 拦截）：真实厂商缩写、
        真实域名、真实库名、真实主机用户名。缺失时脚本仍会跑形态检查，
        并显式提示"身份字面量检查已跳过"。

    规则字段：
      Name      规则名（出现在报告里）
      Severity  'Error' | 'Warn'    只有 Error 会导致非零退出码
      Pattern   .NET 正则（单行匹配）
      Literal   （可选）纯字面量、大小写不敏感的子串匹配，与 Pattern 二选一
      Allow     （可选）命中 token 若包含其中任一子串则豁免
      Why       为什么这条算泄露（写给人看）
#>
@{
    SchemaVersion = 1

    Description = 'MB 客户端逆向报告仓库的脱敏形态规则'

    # ------------------------------------------------------------------
    # §2 占位符表（与 SANITIZATION.md 保持一致）
    # ------------------------------------------------------------------
    Placeholders = @(
        @{ Token = '<WORK>';        Meaning = '本地工作根目录' }
        @{ Token = '<SAMPLE>';      Meaning = '样本解包目录' }
        @{ Token = '<OUT>';         Meaning = '产物目录' }
        @{ Token = '<HOME>';        Meaning = '用户主目录' }
        @{ Token = '<TOOLS>';       Meaning = '逆向工具链根目录' }
        @{ Token = '<UNIDBG>';      Meaning = 'unidbg 源码与构建目录' }
        @{ Token = '<GHIDRA_PROJ>'; Meaning = 'Ghidra 工程库目录' }
        @{ Token = '<FRIDA>';       Meaning = 'frida / frida-server 分发目录' }
        @{ Token = '<EMU>';         Meaning = 'Android 模拟器安装目录' }
        @{ Token = '<PY>';          Meaning = 'Python 解释器目录' }
        @{ Token = '<JDK>';         Meaning = 'Java 运行环境目录' }
        @{ Token = '<user>';        Meaning = '主机用户名' }
    )

    # ------------------------------------------------------------------
    # 白名单：公开商业产品与通用 scheme，命中时不报警
    # ------------------------------------------------------------------
    Allow = @{
        Schemes = @(
            'http', 'https', 'ws', 'wss', 'file', 'content', 'intent', 'market',
            'data', 'javascript', 'about', 'chrome', 'android-app',
            'bankapp', 'bankappgt', 'bankappunion'
        )

        # 公开第三方 SDK 的包名根（出现在报告里是技术必需）
        Packages = @(
            'com.example', 'com.unionpay', 'com.realm', 'com.iflytek',
            'com.tencent', 'com.alipay', 'com.secneo', 'com.ijiami',
            'com.bangcle', 'com.alibaba', 'com.taobao', 'com.huawei',
            'com.android', 'com.google', 'com.sec', 'com.samsung',
            'com.facebook', 'com.bytedance', 'com.meituan',
            'com.xiaomi', 'com.vivo', 'com.oppo', 'com.meizu',
            'com.finogeeks', 'com.hihonor', 'com.coloros'
        )
    }

    # ------------------------------------------------------------------
    # §7 三类检查
    # ------------------------------------------------------------------
    Rules = @(

        # ========== 类 1：路径 ==========
        @{
            Name     = 'PathDriveLetter'
            Severity = 'Error'
            Pattern  = '(?<![A-Za-z0-9])[A-Za-z]:[\\/]'
            Why      = 'Windows 绝对路径（Drive:\ 或 Drive:/）会暴露分析者主机布局'
        }
        @{
            Name     = 'PathUncShare'
            Severity = 'Error'
            Pattern  = '\\\\[A-Za-z0-9._$-]+[\\/]'
            Why      = 'UNC 共享路径会暴露内网主机名'
        }
        @{
            Name     = 'PathUserProfile'
            Severity = 'Error'
            # 只在"路径起点"处判定（行首 / 空白 / 引号 / 括号），
            # 这样 APK 内部的 assets/home/xxx 不会被误判成主机用户目录。
            Pattern  = '(?:^|[\s\x22\x27\x60(\[])[\\/](?:Users|home)[\\/](?!<user>|<HOME>)[A-Za-z0-9._-]{2,}'
            Why      = '用户目录下的具体用户名既是隐私，也泄露主机布局'
        }

        # ========== 类 1：身份形态 ==========
        @{
            Name     = 'CertSubject'
            Severity = 'Error'
            Pattern  = '\bCN\s*=\s*(?![<(（])'
            Why      = '证书主体 CN 的真实值可直接指认签名者；只允许 CN=<redacted>'
        }
        @{
            Name     = 'DomainCn'
            Severity = 'Error'
            Pattern  = '[A-Za-z0-9-]{2,}\.(?:com|net|org)\.cn'
            Why      = '真实自有域名（写 <vendor>.com.cn 时因前导 < 不会命中）'
        }
        @{
            Name     = 'SchemeOpaque'
            Severity = 'Error'
            Pattern  = '\b(?!(?:https?|wss?|file|content|intent|market|data|javascript|about|chrome|android-app|bankapp|bankappgt|bankappunion)\b)[a-z][a-z0-9+.-]{2,15}://'
            Why      = '未登记的深链 scheme 与包名一样，是最好用的样本指纹'
        }
        @{
            Name     = 'PackageId'
            Severity = 'Error'
            Pattern  = '\bcom\.[a-z][a-z0-9_]{2,}\.[a-z0-9_.]+'
            Allow    = @(
                'com.example', 'com.unionpay', 'com.realm', 'com.iflytek',
                'com.tencent', 'com.alipay', 'com.secneo', 'com.ijiami',
                'com.bangcle', 'com.alibaba', 'com.taobao', 'com.huawei',
                'com.android', 'com.google', 'com.sec', 'com.samsung',
                'com.facebook', 'com.bytedance', 'com.meituan',
                'com.xiaomi', 'com.vivo', 'com.oppo', 'com.meizu',
                'com.finogeeks', 'com.hihonor', 'com.coloros'
            )
            Why      = '真实包名（写 com.<vendor>.mobilebank.per 时因 < 不会命中）'
        }

        # ========== 类 2：凭据 ==========
        @{
            Name     = 'Key16Bytes'
            Severity = 'Error'
            Pattern  = '(?<![0-9A-Fa-f])[0-9A-Fa-f]{32}(?![0-9A-Fa-f])'
            Why      = '32 hex = 16 字节，正是 SM4/AES 的密钥长度；只允许留前 8 位'
        }
        @{
            Name     = 'DigestSha1'
            Severity = 'Error'
            Pattern  = '(?<![0-9A-Fa-f])[0-9A-Fa-f]{40}(?![0-9A-Fa-f])'
            Why      = '完整 SHA-1（含 certutil/keytool 指纹）可用于样本库反查'
        }
        @{
            Name     = 'DigestSha256'
            Severity = 'Error'
            Pattern  = '(?<![0-9A-Fa-f])[0-9A-Fa-f]{64}(?![0-9A-Fa-f])'
            Why      = '完整 SHA-256；仓库约定只保留前 16 hex'
        }

        # ========== 类 3：结构性 PII 与残留 ==========
        @{
            Name     = 'HexRunLong'
            Severity = 'Error'
            # 不设右边界：整段连续 hex 只要 >=33 位就直接命中，
            # 避免"56 位一串"这类超长材料从 32 位规则的缝隙里漏过去。
            Pattern  = '(?<![0-9A-Fa-f])[0-9A-Fa-f]{33,}'
            Why      = '连续 hex 超过 32 位，等同于泄露 >=17 字节的密钥/明文材料'
        }
        @{
            Name     = 'HexRunMedium'
            Severity = 'Warn'
            Pattern  = '(?<![0-9A-Fa-f])[0-9A-Fa-f]{24,32}(?![0-9A-Fa-f])'
            Why      = '24–32 位 hex 偏长，建议按约定截到 16 位'
        }
        @{
            Name     = 'KeyAssigned'
            Severity = 'Warn'
            Pattern  = '(?i)\b(?:sm4|aes|des|rc4|key|secret|token|password|passwd)\b\s*[:=]\s*.{0,2}[0-9A-Fa-f]{8,}'
            Why      = 'key=…hex 形式即便截断也容易被误当可用材料'
        }
        @{
            Name     = 'EmailAddress'
            Severity = 'Error'
            Pattern  = '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
            Why      = '真实邮箱属于个人信息'
        }
        @{
            Name     = 'Ipv4Address'
            Severity = 'Warn'
            Pattern  = '(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])'
            # 回环/全零地址是技术必需，且不指向任何环境
            Allow    = @('127.0.0.1', '0.0.0.0', '255.255.255.255')
            Why      = '具体 IP 可能指向内网或分析环境'
        }
        @{
            Name     = 'MobileNumber'
            Severity = 'Warn'
            Pattern  = '(?<!\d)1[3-9]\d{9}(?!\d)'
            Why      = '手机号属于个人信息'
        }
        @{
            Name     = 'LongBase64'
            Severity = 'Warn'
            Pattern  = '[A-Za-z0-9+/]{80,}={0,2}'
            Why      = '超长 base64 串可能是密钥/证书/密文原文'
        }
    )

    # ------------------------------------------------------------------
    # §6 本地覆盖层（不入库）
    # ------------------------------------------------------------------
    LocalOverride = @{
        File = 'scrub-map.local.psd1'
        Keys = @('ForbiddenLiterals', 'ForbiddenRegexes')
        Note = 'ForbiddenLiterals 的 Value 是真实值：目标厂商缩写/域名/库名/用户名'
    }
}
