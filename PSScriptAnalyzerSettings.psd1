# PSScriptAnalyzer (app standards QA-LINT-1). CI lists errors and warnings and fails on errors.
#   Invoke-ScriptAnalyzer -Path . -Recurse -Settings ./PSScriptAnalyzerSettings.psd1
@{
    Severity     = @('Error', 'Warning')
    # Console output is the point of this script (live per-finding feedback).
    # PSUseSingularNouns: the check functions are named after what they audit (Test-SecureBootAndUEFI,
    # Test-LegacyProtocols, …); renaming 36 public check names would be churn without benefit.
    ExcludeRules = @('PSAvoidUsingWriteHost', 'PSUseSingularNouns')
}
