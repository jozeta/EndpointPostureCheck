<#
.SYNOPSIS
    Fails (exit 1) when any .ps1 in the repository has a parse error. Run under both Windows
    PowerShell 5.1 and PowerShell 7: PSScriptAnalyzer reports clean on a script that does not parse.
#>
$failed = 0
foreach ($file in Get-ChildItem -Path (Split-Path -Parent $PSScriptRoot) -Recurse -Filter '*.ps1') {
    $tokens = $null; $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
    foreach ($e in @($errors)) {
        $failed++
        Write-Host ("{0}:{1}:{2}: {3}" -f $file.Name, $e.Extent.StartLineNumber, $e.Extent.StartColumnNumber, $e.Message)
    }
}
Write-Host "PowerShell $($PSVersionTable.PSVersion): $failed parse error(s)"
if ($failed) { exit 1 }
