# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Two independent, zero-dependency security posture auditors that share one design:

- `Invoke-EndpointPostureCheck.ps1`: Windows 11 Enterprise, PowerShell, 142 checks / 34 domains.
- `Invoke-MacPostureCheck.sh`: macOS 15/26, zsh, 185 checks / 32 domains.

Each produces a self-contained HTML dashboard with weighted compliance scoring and framework
mappings, plus optional JSON export and a generated remediation script.

## Running

```powershell
# Windows: elevated PowerShell
.\Invoke-EndpointPostureCheck.ps1 [-ReportPath C:\Reports] [-ExportJson] [-GenerateRemediationScript]
```
```sh
# macOS
sudo ./Invoke-MacPostureCheck.sh [--report-path ~/Reports] [--export-json] [--generate-remediation]
```

Both refuse to run without admin/root rather than produce a partial report. A full Windows run
takes 60–90 s. There is no automated test suite: verify by running on a real (or VM) endpoint and
reviewing the HTML report.

## Build (macOS edition)

`build.sh` concatenates `src/*.zsh` (in filename order) into `Invoke-MacPostureCheck.sh` and
stamps a "do not edit directly" header. **`src/` and the zsh tests are kept locally and are not
in the repo** (gitignored, waived in `.claude-standards`). When `src/` is present, edit the
modules there, run `./build.sh`, and run the zsh tests with `tests/run-tests.sh`. Commit the
rebuilt `Invoke-MacPostureCheck.sh`.

If `src/` is missing, it can be recovered without loss from the built script, since every module
is marked `# ---- <name>.zsh ----`. Split on those markers, restore each module's shebang line,
and drop the one blank line `build.sh` adds before each marker. Then rebuild and diff to confirm.

## Design rules (from README "Design Principles")

- **Fault isolation:** every check runs in its own try/catch; one failing check must never abort
  the run or other checks.
- **Honesty over false precision:** when the OS has no reliable API, report `INFO` (or `WARN`
  with the reason), never a guessed `PASS`/`FAIL`. Statuses are `PASS`, `WARN`, `FAIL`, `INFO`.
- **Defaults aren't findings:** don't flag normal OS-default states as failures.
- **No duplicate or contradictory checks** that evaluate the same setting differently.
- **Performance-bounded:** file and log sweeps are capped, never full-disk recursion.
- Remediation scripts must support `-WhatIf` and require `-Force` (Windows) before changing
  anything. Never make the auditor itself change system state.
- Keep both editions in step when adding a check that exists on both platforms, and update the
  check counts and domain tables in README.md.

## App standards

This repo follows the app standards in `~/Desktop/code/tools/standards/STANDARDS.md` (rule IDs,
severities; decisions and waivers in `.claude-standards`). `claude-check --repo .` checks it.

```powershell
Invoke-ScriptAnalyzer -Path . -Recurse -Settings ./PSScriptAnalyzerSettings.psd1   # lint
Invoke-Pester -Path tests                                                         # local Pester 5 tests
```

`tests/` stays local and unpublished (gitignored; waived in `.claude-standards`). The Pester tests
load helper functions from the script's syntax tree and never run the audit. CI lints on Windows,
plus ShellCheck on `build.sh` and `zsh -n` on the macOS script.

