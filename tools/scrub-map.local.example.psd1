<#
    scrub-map.local.example.psd1 —— 本地覆盖层模板（本模板可入库）

    用法：
      1. 复制为 tools/scrub-map.local.psd1（该文件名已被 .gitignore 拦截）；
      2. 把 Value 换成真实值；
      3. 回到仓库根目录跑 tools/check-sanitization.ps1，确保 0 命中。

    为什么要把真实值放在"不入库"的文件里：
      检查器需要知道"哪些字面量算泄露"，但把它写进公开仓库等于把答案公布出来。
      因此公开层只描述形态（路径、16 字节密钥、40/64 位摘要……），
      真实身份词只存在于本地层。两者合起来才能证明"没有泄露产品身份"。

    注意：Value 采用大小写不敏感的子串匹配，因此不要写过短的词
    （脚本会拒绝长度 < 2 的规则），也不要写会在技术术语里频繁出现的通用词。
#>
@{
    SchemaVersion = 1

    ForbiddenLiterals = @(
        # 目标软件的厂商缩写 / 应用名 / 拼音 / 英文名
        @{ Label = 'vendor-abbrev'; Value = '<VENDOR_ABBR>'; Severity = 'Error'; Why = '厂商缩写会直接指认样本' }
        @{ Label = 'vendor-name';   Value = '<VENDOR_NAME>'; Severity = 'Error'; Why = '应用名同上' }

        # 自有域名与深链 scheme（含子域前缀片段）
        @{ Label = 'domain';        Value = '<VENDOR_DOMAIN>'; Severity = 'Error'; Why = '自有域名' }
        @{ Label = 'scheme';        Value = '<VENDOR_SCHEME>'; Severity = 'Error'; Why = '深链 scheme' }

        # 含厂商缩写的库名 / JAR 名
        @{ Label = 'lib-prefix';    Value = 'lib<VENDOR>';      Severity = 'Error'; Why = '库名含厂商缩写' }

        # 主机用户名（大小写不敏感，注意别写成常见英文单词）
        @{ Label = 'host-user';     Value = '<USERNAME>';       Severity = 'Error'; Why = '主机用户名' }
    )

    # 需要更复杂匹配时用正则；同样只放在本地层
    ForbiddenRegexes = @(
        # @{ Name = 'Local:custom'; Severity = 'Error'; Pattern = '<正则>'; Why = '<原因>' }
    )
}
