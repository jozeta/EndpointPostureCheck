<#
.SYNOPSIS
    CI check of a full audit run: validates the JSON export and HTML dashboard that
    Invoke-EndpointPostureCheck.ps1 or Invoke-MacPostureCheck.sh wrote to -ReportDir.

.DESCRIPTION
    Fails (exit 1) on structural problems only: missing or invalid output, too few findings or
    domains, unknown statuses, unreplaced template tokens, or a run where most checks could not
    query the system. Checks that report "Query failed" on a CI runner (Windows Server, no
    Secure Boot, no console user) are expected and listed in the job summary, not failed.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ReportDir,
    [Parameter(Mandatory)] [int]$MinFindings,
    [Parameter(Mandatory)] [int]$MinDomains,
    [string]$Label = 'audit',
    [switch]$ExpectBaseline,
    [switch]$ExpectExceptions,
    [string[]]$ExpectInventory = @()
)

$ErrorActionPreference = 'Stop'
$problems = [System.Collections.Generic.List[string]]::new()

$json = Get-ChildItem -LiteralPath $ReportDir -Filter '*.json' | Sort-Object LastWriteTime | Select-Object -Last 1
$html = Get-ChildItem -LiteralPath $ReportDir -Filter '*.html' | Sort-Object LastWriteTime | Select-Object -Last 1
if (-not $json) { $problems.Add('No JSON export was written') }
if (-not $html) { $problems.Add('No HTML dashboard was written') }

$report = $null
if ($json) {
    try { $report = Get-Content -LiteralPath $json.FullName -Raw | ConvertFrom-Json }
    catch { $problems.Add("JSON export is not valid JSON: $($_.Exception.Message)") }
}

$failedQueries = @()
$tables = @()
if ($report) {
    $findings = @($report.Findings)
    if ($findings.Count -lt $MinFindings) { $problems.Add("Only $($findings.Count) findings (expected at least $MinFindings)") }
    $domains = @($findings | Select-Object -ExpandProperty Category -Unique)
    if ($domains.Count -lt $MinDomains) { $problems.Add("Only $($domains.Count) domains (expected at least $MinDomains)") }
    $badStatus = @($findings | Where-Object { $_.Status -notin @('PASS', 'WARN', 'FAIL', 'INFO') })
    if ($badStatus.Count) { $problems.Add("$($badStatus.Count) finding(s) with an unknown status, e.g. '$($badStatus[0].Status)' on '$($badStatus[0].Control)'") }
    $noControl = @($findings | Where-Object { -not $_.Control -or -not $_.Category })
    if ($noControl.Count) { $problems.Add("$($noControl.Count) finding(s) without a control or category name") }
    $failedQueries = @($findings | Where-Object { "$($_.CurrentValue)" -match '(?i)query failed|unable to|failed:' })
    if ($findings.Count -and ($failedQueries.Count / $findings.Count) -gt 0.4) {
        $problems.Add("$($failedQueries.Count) of $($findings.Count) findings could not query the system (over 40%)")
    }
    # A check's catch block repeating its control name usually means the first call threw (for
    # example "Cannot bind parameter ... specified more than once" on Windows PowerShell 5.1).
    $dupes = @($findings | Group-Object -Property { "$($_.Category)|$($_.Control)" } | Where-Object { $_.Count -gt 1 })
    if ($dupes.Count) { $problems.Add("$($dupes.Count) control(s) reported more than once, e.g. '$($dupes[0].Name)'") }
    $bindErrors = @($findings | Where-Object { "$($_.CurrentValue) $($_.Recommendation)" -match 'Cannot bind parameter|parameter cannot be found|specified more than once' })
    if ($bindErrors.Count) { $problems.Add("$($bindErrors.Count) finding(s) carry a PowerShell parameter binding error, e.g. on '$($bindErrors[0].Control)'") }
    if ($ExpectBaseline -and -not "$($report.BaselineFile)") { $problems.Add('BaselineFile is empty although a baseline was passed') }
    if ($null -eq $report.ComplianceScore) { $problems.Add('ComplianceScore missing') }
    if ($ExpectExceptions) {
        if (-not "$($report.ExceptionFile)") { $problems.Add('ExceptionFile is empty although an exceptions file was passed') }
        if (-not @($findings | Where-Object { $_.Control -eq 'Accepted Risk Exceptions' }).Count) { $problems.Add('No "Accepted Risk Exceptions" finding') }
    }
    $tables = @()
    if ($report.Inventory -and $report.Inventory.tables) { $tables = @($report.Inventory.tables) }
    foreach ($id in $ExpectInventory) {
        $t = @($tables | Where-Object { $_.id -eq $id })
        if (-not $t.Count) { $problems.Add("Inventory table '$id' missing") }
        elseif (-not @($t[0].rows).Count) { $problems.Add("Inventory table '$id' is empty") }
        elseif (@($t[0].rows | Where-Object { @($_).Count -ne @($t[0].columns).Count }).Count) { $problems.Add("Inventory table '$id' has rows whose cell count differs from its columns") }
    }
}

if ($html) {
    $text = Get-Content -LiteralPath $html.FullName -Raw
    $tokens = @([regex]::Matches($text, '\{\{[A-Z_]+\}\}') | ForEach-Object Value | Select-Object -Unique)
    if ($tokens.Count) { $problems.Add("Unreplaced template token(s) in the HTML: $($tokens -join ', ')") }
    if ($text -notmatch '</html>\s*$') { $problems.Add('HTML dashboard is truncated (no closing </html>)') }
    if ($html.Length -gt 16MB) { $problems.Add("HTML dashboard is $([math]::Round($html.Length / 1MB, 1)) MB (limit 16 MB)") }
}

# Job summary: status counts and every check that could not query the system.
$summary = [System.Text.StringBuilder]::new()
[void]$summary.AppendLine("### $Label")
if ($report) {
    $s = $report.Summary
    [void]$summary.AppendLine("Score $($report.ComplianceScore)% ($($report.RiskLevel)); $(@($report.Findings).Count) findings: PASS $($s.Pass), FAIL $($s.Fail), WARN $($s.Warn), INFO $($s.Info). OS: $($report.OperatingSystem)")
    if ($tables.Count) {
        [void]$summary.AppendLine('')
        [void]$summary.AppendLine('Inventory: ' + (($tables | ForEach-Object { "$($_.title) $(@($_.rows).Count)" }) -join ', '))
        foreach ($t in $tables) { if ($t.note) { [void]$summary.AppendLine("- $($t.title): $($t.note)") } }
    }
    if ($failedQueries.Count) {
        [void]$summary.AppendLine('')
        [void]$summary.AppendLine("<details><summary>$($failedQueries.Count) check(s) could not query the system</summary>")
        [void]$summary.AppendLine('')
        foreach ($f in $failedQueries) {
            $msg = ("$($f.CurrentValue) $($f.Recommendation)" -replace '\s+', ' ')
            if ($msg.Length -gt 300) { $msg = $msg.Substring(0, 300) + '...' }
            [void]$summary.AppendLine("- **$($f.Control)**: $($msg -replace '\|', '/')")
        }
        [void]$summary.AppendLine('</details>')
    }
}
if ($problems.Count) {
    [void]$summary.AppendLine('')
    [void]$summary.AppendLine('**Problems:**')
    foreach ($p in $problems) { [void]$summary.AppendLine("- $p") }
}
$summaryText = $summary.ToString()
Write-Host $summaryText
if ($env:GITHUB_STEP_SUMMARY) { Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY -Value $summaryText }

if ($problems.Count) { exit 1 }
