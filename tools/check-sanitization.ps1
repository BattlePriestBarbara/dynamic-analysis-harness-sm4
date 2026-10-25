<#
.SYNOPSIS
    脱敏自检：确认仓库内的文本没有残留路径、身份与凭据。

.DESCRIPTION
    三类检查（对应 SANITIZATION.md §7）：
      1) 形态：绝对路径、用户目录、包名、域名、深链 scheme、证书主体；
      2) 凭据：16 字节密钥、完整 SHA-1/SHA-256、赋值式密钥；
      3) PII：邮箱、手机号、IPv4、超长 base64（建议级）。

    规则来源：
      tools/scrub-map.psd1         公开层（可入库，只描述形态）
      tools/scrub-map.local.psd1   本地层（**不入库**）：真实厂商缩写/域名/库名/用户名

    本地层缺失时，形态检查照常执行，但会显式提示"身份字面量检查已跳过"——
    也就是说：提交前请确保本地层存在，否则只能证明"没有泄露路径与凭据"，
    不能证明"没有泄露产品身份"。

.EXAMPLE
    pwsh -File tools/check-sanitization.ps1

.EXAMPLE
    pwsh -File tools/check-sanitization.ps1 -Report
    只列出命中，不因 Error 失败（排查用）。

.NOTES
    退出码：0 = 通过；1 = 存在 Error 级命中；2 = 规则/参数问题。
    本脚本只读，不修改任何文件。
#>
[CmdletBinding()]
param(
    # 仓库根目录；默认取脚本所在目录的上一级
    [string]$Root,

    # 只扫描指定文件或目录（相对或绝对），默认扫描整个仓库
    [string[]]$Path,

    # 只报告，不因命中而失败
    [switch]$Report,

    # 只打印规则表后退出
    [switch]$ListRules,

    # 不打印逐条命中，只打印汇总
    [switch]$Quiet
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:RuleCount    = 0
$script:LocalCount   = 0
$script:LocalLoaded  = $false

function Split-Display {
    param([string]$Text, [int]$Max = 28)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    if ($Text.Length -le $Max) { return $Text }
    return $Text.Substring(0, 8) + [char]0x2026 + $Text.Substring($Text.Length - 4)
}

function Read-DataFile {
    param([string]$LiteralPath)
    return Import-PowerShellDataFile -LiteralPath $LiteralPath
}

function Get-TargetFiles {
    param([string]$Base, [string[]]$Explicit)

    $textExt = @('.md', '.txt', '.ps1', '.psd1', '.psm1', '.yml', '.yaml', '.json', '.toml', '.ini', '.cfg')
    $textName = @('.gitignore', '.gitattributes', '.editorconfig')

    if ($Explicit) {
        $out = New-Object System.Collections.Generic.List[object]
        foreach ($p in $Explicit) {
            $resolved = $p
            if (-not [System.IO.Path]::IsPathRooted($p)) {
                $resolved = Join-Path $Base $p
            }
            if (Test-Path -LiteralPath $resolved -PathType Leaf) {
                $out.Add((Get-Item -LiteralPath $resolved))
            }
            elseif (Test-Path -LiteralPath $resolved -PathType Container) {
                Get-ChildItem -LiteralPath $resolved -File -Recurse -Force -ErrorAction SilentlyContinue |
                    Where-Object { $textExt -contains $_.Extension.ToLower() -or $textName -contains $_.Name } |
                    ForEach-Object { $out.Add($_) }
            }
            else {
                Write-Warning ("路径不存在，已跳过: " + $p)
            }
        }
        return $out
    }

    Get-ChildItem -LiteralPath $Base -File -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object {
            $_.FullName -notmatch '[\\/]\.git[\\/]' -and
            ($textExt -contains $_.Extension.ToLower() -or $textName -contains $_.Name)
        }
}

# ======================================================================
# 载入规则
# ======================================================================
$scriptDir = $PSScriptRoot
if ([string]::IsNullOrEmpty($scriptDir)) { $scriptDir = (Get-Location).Path }

$mapPath = Join-Path $scriptDir 'scrub-map.psd1'
if (-not (Test-Path -LiteralPath $mapPath -PathType Leaf)) {
    Write-Host ('[FAIL] 找不到规则表: ' + $mapPath) -ForegroundColor Red
    exit 2
}

try {
    $map = Read-DataFile -LiteralPath $mapPath
}
catch {
    Write-Host ('[FAIL] 规则表无法解析: ' + $_.Exception.Message) -ForegroundColor Red
    exit 2
}

if ([string]::IsNullOrEmpty($Root)) {
    $Root = Split-Path -Parent $scriptDir
}
$Root = (Resolve-Path -LiteralPath $Root).Path

$rules = New-Object System.Collections.Generic.List[object]
foreach ($r in $map['Rules']) { $rules.Add($r) }
$script:RuleCount = $rules.Count

$localOverride = $map['LocalOverride']
$localFile = 'scrub-map.local.psd1'
if ($localOverride -and $localOverride.ContainsKey('File')) { $localFile = $localOverride['File'] }
$localPath = Join-Path $scriptDir $localFile

$localNotes = New-Object System.Collections.Generic.List[string]
if (Test-Path -LiteralPath $localPath -PathType Leaf) {
    try { $local = Read-DataFile -LiteralPath $localPath }
    catch {
        Write-Host ('[FAIL] 本地覆盖层无法解析: ' + $_.Exception.Message) -ForegroundColor Red
        exit 2
    }
    $script:LocalLoaded = $true

    if ($local.ContainsKey('ForbiddenLiterals')) {
        foreach ($lit in $local['ForbiddenLiterals']) {
            $severity = 'Error'
            if ($lit.ContainsKey('Severity')) { $severity = $lit['Severity'] }
            $label = 'literal'
            if ($lit.ContainsKey('Label')) { $label = $lit['Label'] }
            $why = '真实身份字面量（来自本地覆盖层）'
            if ($lit.ContainsKey('Why')) { $why = $lit['Why'] }
            $rules.Add(@{
                Name     = 'Local:' + $label
                Severity = $severity
                Literal  = $lit['Value']
                Why      = $why
            })
            $script:LocalCount++
        }
    }

    if ($local.ContainsKey('ForbiddenRegexes')) {
        foreach ($rx in $local['ForbiddenRegexes']) {
            $rules.Add($rx)
            $script:LocalCount++
        }
    }
}

if ($ListRules) {
    Write-Host ''
    Write-Host ('规则表: ' + $mapPath + '  共 ' + $script:RuleCount + ' 条') -ForegroundColor Cyan
    Write-Host ('本地层: ' + $localPath + '  ' + $(if ($script:LocalLoaded) { '已载入 ' + $script:LocalCount + ' 条' } else { '缺失' })) -ForegroundColor Cyan
    Write-Host ''
    $i = 0
    foreach ($r in $rules) {
        $i++
        $kindLabel = 'Pattern'
        if ($r.ContainsKey('Literal')) { $kindLabel = 'Literal' }
        Write-Host ('  {0,2}. [{1,-5}] {2,-20} {3}' -f $i, $r['Severity'], $r['Name'], $kindLabel) -ForegroundColor Gray
        Write-Host ('      ' + $r['Why']) -ForegroundColor DarkGray
    }
    Write-Host ''
    exit 0
}

# ======================================================================
# 预编译正则：任何一条写错都应立刻失败，而不是静默跳过
# ======================================================================
$compiled = New-Object System.Collections.Generic.List[object]
foreach ($r in $rules) {
    $entry = @{ Rule = $r; Rx = $null; Literal = $null }
    if ($r.ContainsKey('Literal')) {
        $entry.Literal = [string]$r['Literal']
        if ($entry.Literal.Length -lt 2) {
            Write-Host ('[FAIL] 本地规则字面量过短（<2 字符），拒绝执行: ' + $r['Name']) -ForegroundColor Red
            exit 2
        }
    }
    else {
        try {
            $entry.Rx = New-Object System.Text.RegularExpressions.Regex([string]$r['Pattern'], 'Compiled')
        }
        catch {
            Write-Host ('[FAIL] 正则无法编译: ' + $r['Name'] + ' -> ' + $_.Exception.Message) -ForegroundColor Red
            exit 2
        }
    }
    $compiled.Add($entry)
}

# ======================================================================
# 扫描
# ======================================================================
$files = @(Get-TargetFiles -Base $Root -Explicit $Path)
if ($localPath) {
    # 本地层自身装着真实值：它被 .gitignore 挡在库外，不参与扫描（否则必然自命中）
    $files = @($files | Where-Object { $_.FullName -ne $localPath })
}
if ($files.Count -eq 0) {
    Write-Host '[FAIL] 没有可扫描的文本文件，请检查 -Root / -Path。' -ForegroundColor Red
    exit 2
}

$hits     = New-Object System.Collections.Generic.List[object]
$oversize = New-Object System.Collections.Generic.List[object]
$seen     = New-Object System.Collections.Generic.HashSet[string]
$lineSum  = 0

foreach ($f in $files) {
    $rel = $f.FullName
    if ($rel.StartsWith($Root, [System.StringComparison]::OrdinalIgnoreCase)) {
        $rel = $rel.Substring($Root.Length).TrimStart('\', '/')
    }

    if ($f.Length -gt 1048576) {
        $oversize.Add([pscustomobject]@{ File = $rel; Bytes = $f.Length })
    }

    $lines = [System.IO.File]::ReadAllLines($f.FullName, [System.Text.Encoding]::UTF8)
    $lineSum += $lines.Length

    for ($i = 0; $i -lt $lines.Length; $i++) {
        $line = $lines[$i]
        if ([string]::IsNullOrWhiteSpace($line)) { continue }

        foreach ($c in $compiled) {
            if ($null -ne $c.Literal) {
                if ($line.IndexOf($c.Literal, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                    $key = $rel + '|' + ($i + 1) + '|' + $c.Rule['Name']
                    if ($seen.Add($key)) {
                        $ctx = $line.Trim()
                        if ($ctx.Length -gt 160) { $ctx = $ctx.Substring(0, 160) + [char]0x2026 }
                        $hits.Add([pscustomobject]@{
                            File     = $rel
                            Line     = $i + 1
                            Rule     = $c.Rule['Name']
                            Severity = $c.Rule['Severity']
                            Matched  = $c.Literal
                            Why      = $c.Rule['Why']
                            Context  = $ctx
                        })
                    }
                }
                continue
            }

            foreach ($m in $c.Rx.Matches($line)) {
                $tok = $m.Value
                if ($c.Rule.ContainsKey('Allow')) {
                    $skip = $false
                    foreach ($a in $c.Rule['Allow']) {
                        if ($tok.IndexOf([string]$a, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                            $skip = $true
                            break
                        }
                    }
                    if ($skip) { continue }
                }

                $key = $rel + '|' + ($i + 1) + '|' + $c.Rule['Name'] + '|' + $tok
                if (-not $seen.Add($key)) { continue }

                $ctx = $line.Trim()
                if ($ctx.Length -gt 160) { $ctx = $ctx.Substring(0, 160) + [char]0x2026 }
                $hits.Add([pscustomobject]@{
                    File     = $rel
                    Line     = $i + 1
                    Rule     = $c.Rule['Name']
                    Severity = $c.Rule['Severity']
                    Matched  = Split-Display -Text $tok
                    Why      = $c.Rule['Why']
                    Context  = $ctx
                })
            }
        }
    }
}

# ======================================================================
# 附加一致性检查（属"仓库卫生"，不是脱敏本身）
# ======================================================================
$notes = New-Object System.Collections.Generic.List[string]

$giPath = Join-Path $Root '.gitignore'
if (Test-Path -LiteralPath $giPath -PathType Leaf) {
    $giText = [System.IO.File]::ReadAllText($giPath, [System.Text.Encoding]::UTF8)
    if ($giText -notmatch '(?m)^/\*\s*$') {
        $notes.Add('.gitignore 缺少独立一行 /*（白名单模式失效，样本可能被误提交）')
    }
    if ($giText -notmatch 'scrub-map\.local\.psd1') {
        $notes.Add('.gitignore 未拦截 tools/scrub-map.local.psd1（本地层含真实身份值，必须挡在库外）')
    }
}
else {
    $notes.Add('缺少 .gitignore')
}

foreach ($of in $oversize) {
    $notes.Add('文本文件异常大（' + [math]::Round($of.Bytes / 1KB) + ' KB），疑似误入库的产物: ' + $of.File)
}

$gitCmd = Get-Command git -ErrorAction SilentlyContinue
if ($gitCmd -and (Test-Path -LiteralPath (Join-Path $Root '.git') -PathType Container)) {
    # core.quotepath=false：否则中文路径会被八进制转义并带上引号，GetExtension 会抛异常
    $tracked = & git -C $Root -c core.quotepath=false ls-files 2>$null
    if ($LASTEXITCODE -eq 0 -and $tracked) {
        $badExt = @('.apk', '.so', '.dex', '.bin', '.img', '.zip', '.jar', '.png', '.doc', '.docx', '.pdf', '.jsonl', '.db', '.pcap')
        foreach ($t in $tracked) {
            try {
                $ext = [System.IO.Path]::GetExtension($t).ToLower()
            }
            catch {
                $notes.Add('git 跟踪了无法解析的路径: ' + $t)
                continue
            }
            if ($badExt -contains $ext) { $notes.Add('git 已跟踪二进制/产物文件: ' + $t) }
        }
        if ($tracked -contains 'tools/scrub-map.local.psd1') {
            $notes.Add('tools/scrub-map.local.psd1 已被 git 跟踪，必须移出索引')
        }
    }
}

# ======================================================================
# 输出
# ======================================================================
$errors = @($hits | Where-Object { $_.Severity -eq 'Error' })
$warns  = @($hits | Where-Object { $_.Severity -ne 'Error' })

$bar = '=' * 74
Write-Host ''
Write-Host $bar -ForegroundColor DarkCyan
Write-Host ' 脱敏自检  sanitization check' -ForegroundColor Cyan
Write-Host $bar -ForegroundColor DarkCyan
Write-Host (' 仓库根目录   : ' + $Root)
Write-Host (' 规则         : 公开层 ' + $script:RuleCount + ' 条' + $(if ($script:LocalLoaded) { ' + 本地层 ' + $script:LocalCount + ' 条' } else { '（无本地层）' }))
Write-Host (' 本地覆盖层   : ' + $(if ($script:LocalLoaded) { $localPath } else { '未找到 ' + $localPath }))
Write-Host (' 扫描         : ' + $files.Count + ' 个文件 / ' + $lineSum + ' 行')
Write-Host $bar -ForegroundColor DarkCyan
Write-Host ''

if ($hits.Count -eq 0) {
    Write-Host ' 未命中任何规则。' -ForegroundColor Green
}
else {
    $currentFile = ''
    foreach ($h in ($hits | Sort-Object File, Line, Rule)) {
        if ($h.File -ne $currentFile) {
            $currentFile = $h.File
            Write-Host ''
            Write-Host ('-- ' + $currentFile) -ForegroundColor White
        }
        $color = 'Yellow'
        if ($h.Severity -eq 'Error') { $color = 'Red' }
        if (-not $Quiet) {
            Write-Host ('   ' + $h.Line + ':' + $h.Rule) -ForegroundColor $color -NoNewline
            Write-Host ('  [' + $h.Severity + ']') -ForegroundColor $color
            Write-Host ('      命中 : ' + $h.Matched) -ForegroundColor Gray
            Write-Host ('      原因 : ' + $h.Why) -ForegroundColor DarkGray
            Write-Host ('      原文 : ' + $h.Context) -ForegroundColor DarkGray
        }
        elseif ($h.Severity -eq 'Error') {
            Write-Host ('   ' + $h.Line + ':' + $h.Rule + '  ' + $h.Matched) -ForegroundColor $color
        }
    }
}

Write-Host ''
Write-Host $bar -ForegroundColor DarkCyan
Write-Host (' 汇总: ERROR ' + $errors.Count + ' / WARN ' + $warns.Count + ' / 文件 ' + $files.Count) -ForegroundColor Cyan

if ($notes.Count -gt 0) {
    Write-Host ''
    Write-Host ' 仓库卫生:' -ForegroundColor Yellow
    foreach ($n in $notes) { Write-Host ('   - ' + $n) -ForegroundColor Yellow }
}

if (-not $script:LocalLoaded) {
    Write-Host ''
    Write-Host ' 注意: 本地覆盖层缺失 —— 形态检查已执行，但「真实厂商缩写 / 域名 / 库名 /' -ForegroundColor Yellow
    Write-Host '       主机用户名」这类字面量检查被跳过。提交前请按 SANITIZATION.md §7 补上' -ForegroundColor Yellow
    Write-Host '       tools/scrub-map.local.psd1（该文件被 .gitignore 拦截，不会入库）。' -ForegroundColor Yellow
}

Write-Host ''
if ($errors.Count -gt 0) {
    Write-Host (' [FAIL] 存在 ' + $errors.Count + ' 处 Error 级命中，禁止提交。') -ForegroundColor Red
}
elseif ($notes.Count -gt 0) {
    Write-Host ' [PASS] 无 Error 级命中；仓库卫生项见上，建议先处理。' -ForegroundColor Green
}
else {
    Write-Host ' [PASS] 无 Error 级命中，可以提交。' -ForegroundColor Green
}
Write-Host $bar -ForegroundColor DarkCyan
Write-Host ''

if ($Report) { exit 0 }
if ($errors.Count -gt 0) { exit 1 }
exit 0
