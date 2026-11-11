# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Two independent, zero-dependency security posture auditors that share one design:

- `Invoke-EndpointPostureCheck.ps1`: Windows 11 Enterprise, PowerShell, 180 checks / 36 domains (plus `-BaselinePath` and `-ExceptionPath`).
- `Invoke-MacPostureCheck.sh`: macOS 15/26, zsh, 221 checks / 32 domains.

Each produces a self-contained HTML dashboard with weighted compliance scoring and framework
mappings, plus optional JSON export and a generated remediation script.

## Running

```powershell
# Windows: elevated PowerShell
.\Invoke-EndpointPostureCheck.ps1 [-ReportPath C:\Reports] [-ExportJson] [-GenerateRemediationScript]
```
```sh
# macOS
sudo ./Invoke-MacPostureCheck.sh [--report-path ~/Reports] [--export-json] [--generate-remediation] [--generate-profile]
```

Both refuse to run without admin/root rather than produce a partial report. A full Windows run
takes 60–90 s, a full macOS run about 30–60 s. The macOS edition has a local zsh test suite
(`tests/run-tests.sh`, about 600 assertions with stubbed system commands); still verify on a real
(or VM) endpoint and review the HTML report.

**Never run `sfltool` unprivileged** (including through an unprivileged smoke run of the audit):
without root it opens a GUI admin-password dialog that a background process can't answer, and
the run hangs. Stub `sfltool` in unprivileged runs; a real `sudo` run never prompts.

## Build (macOS edition)

`build.sh` concatenates `src/*.zsh` (in filename order) into `Invoke-MacPostureCheck.sh` and
stamps a "do not edit directly" header. **`src/` and the zsh tests are kept locally and are not
in the repo** (gitignored, waived in `.claude-standards`). When `src/` is present, edit the
modules there, run `./build.sh`, and run the zsh tests with `tests/run-tests.sh`. Commit the
rebuilt `Invoke-MacPostureCheck.sh`.

**Version:** `VERSION` is the one source (semver). `build.sh` stamps it into `SCRIPT_VERSION` in
the macOS build and `$Script:ScriptVersion` in the `.ps1`; CI fails unless both scripts, a
`## <version> (date)` CHANGELOG heading and the README's `**Version x.y.z**` line all agree.
To release: edit `VERSION`, run `./build.sh`, move CHANGELOG's Unreleased entries under the new
heading, and update the README version line and "What's new".

Both dashboards use the vendored Låda Glass design (`vendor/lada-glass/<version>/`). `build.sh`
also rewrites the `LADA-GLASS-ASSETS` region of `Invoke-EndpointPostureCheck.ps1` from it (never
edit that region by hand). The Windows `Get-HtmlTemplate` is a port of the macOS template: change
the dashboard CSS/JS in `src/91-report-html.zsh` and copy it to the `.ps1`; the local test
`tests/test-report-windows.zsh` fails if they differ. Keep the `.ps1` pure ASCII (Windows
PowerShell 5.1 reads a BOM-less script as ANSI).

If `src/` is missing, it can be recovered without loss from the built script, since every module
is marked `# ---- <name>.zsh ----`. Split on those markers, restore each module's shebang line,
and drop the one blank line `build.sh` adds before each marker. Then rebuild and diff to confirm.

Backup of `src/`, `tests/` and `build.sh` (local, not on GitHub): iCloud Drive
`Backups/EndpointPostureCheck-dev/` with dated `snapshots/` and a `latest/` mirror. Refresh it
after changing the sources.

## Design rules (from README "Design Principles")

- **Fault isolation:** every check runs in its own try/catch; one failing check must never abort
  the run or other checks.
- **Honesty over false precision:** when the OS has no reliable API, report `INFO` (or `WARN`
  with the reason), never a guessed `PASS`/`FAIL`. Statuses are `PASS`, `WARN`, `FAIL`, `INFO`.
- **Defaults aren't findings:** don't flag normal OS-default states as failures.
- **No duplicate or contradictory checks** that evaluate the same setting differently.
- **Never put file- or user-derived values into zsh arithmetic** (`(( ))`, `$(( ))`, or
  `[[ -lt/-le/-eq ... ]]`): zsh evaluates command substitution inside array subscripts there,
  so a value like `path[$(cmd)]` from a user's preference or JSON file runs as root during an
  audit. Validate with `[[ $v == <-> ]]` (digits only) first, or compare as strings.
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
plus ShellCheck on `build.sh` and `zsh -n` on the macOS script, and runs the full audit for real:
Windows PowerShell 5.1 and PowerShell 7 on `windows-latest`, `sudo` on `macos-latest`, each twice
(the second run with the first one's JSON as baseline). `ci/Test-ReportOutput.ps1` validates the
output and lists every check that could not query the runner in the job summary; the reports are
uploaded as build artifacts.


## Working on a Windows machine

A Windows clone has only the published files: no `src/` and no `tests/` (both gitignored), and
none of the Mac's Claude memory or global `~/.claude/CLAUDE.md`. These rules carry over:

- Don't push, change repo settings or publish releases unless the user asks. Once a plan is
  agreed, build every step, then commit and push to `main` without asking between steps
  (CI verifies). Never force-push, never `--no-verify`, stage only the files you changed.
- Bump the version on every push that changes a script (semver), and update CHANGELOG
  (newest first, "Unreleased") and the README's version and "What's new" in the same commit.
  Without `build.sh` on Windows, edit `VERSION`, the `$Script:ScriptVersion` line in the `.ps1`
  and the single `SCRIPT_VERSION="..."` line in `Invoke-MacPostureCheck.sh` by hand (the only
  edit allowed in that file); CI checks they agree.
- Keep the `.ps1` pure ASCII. Don't edit the `LADA-GLASS-ASSETS` region.
- **Don't change the dashboard CSS/JS in `Get-HtmlTemplate` on Windows.** It must stay identical
  to `src/91-report-html.zsh`, which only exists on the Mac. If it really has to change, say so
  in the commit message ("needs Mac port") so the Mac session copies it back.
- Don't edit `Invoke-MacPostureCheck.sh` (apart from that version line): it is generated from
  `src/` on the Mac.
- Reports from a real machine describe that machine's weaknesses: never commit, push or
  publish them (`*.html` / `*.json` are already gitignored).

**Setup (once):**

```powershell
winget install --id Git.Git -e; winget install --id GitHub.cli -e; winget install --id Microsoft.PowerShell -e
gh auth login
git clone https://github.com/jozeta/EndpointPostureCheck.git; cd EndpointPostureCheck
Install-Module Pester -MinimumVersion 5.0 -Scope CurrentUser -Force -SkipPublisherCheck
Install-Module PSScriptAnalyzer -Scope CurrentUser -Force
```

The Pester tests are in the iCloud backup, if iCloud for Windows is installed:
`Copy-Item -Recurse "$env:USERPROFILE\iCloudDrive\Backups\EndpointPostureCheck-dev\latest\tests" .`
(gitignored, so they stay local). Without them, verify with PSScriptAnalyzer and CI.

**Running the audit:** Claude can't elevate. The user runs it in an elevated PowerShell
(Windows PowerShell 5.1 and `pwsh` both work):

```powershell
powershell -ExecutionPolicy Bypass -File .\Invoke-EndpointPostureCheck.ps1 -ReportPath C:\Reports -ExportJson
```

Then read `C:\Reports\*.json` and review the HTML (open it in a browser).

### Next steps (handoff from the Mac, 2026-11-11)

Version 1.1.0 is pushed. Windows code has so far only run on CI (Windows Server 2025), so the
job on this machine is **the first real Windows 11 run**. 1.1.0 changed several Windows checks
from reading code alone, so look at these first: the current Wi-Fi connection (now per adapter;
with location services off on 24H2+ it should say location access is needed), Wi-Fi Profile
Security (INFO, not PASS, when there's no profile list), removable storage (PASS only when writes
are blocked; check what `Get-MpComputerStatus` reports as `DeviceControlDefaultEnforcement`),
connected devices (USB 3 SSDs found through `Get-Disk`; built-in keyboard not counted) and the
named-pipe list (now native `FindFirstFileW`; the pipe count should match `[System.IO.Directory]::GetFiles('\\.\pipe\').Count`).

1. Run the audit as above (5.1, then `pwsh`). Check for checks that errored or report "could
   not query", false positives on normal Windows 11 defaults, and empty inventory tables.
   Check especially the parts CI can't test: Wi-Fi (`Test-WifiProfileSecurity`,
   `Test-WifiCurrentConnection`), USB/peripherals (`Test-ConnectedPeripheralInventory`,
   `Test-RemovableStorageAccessPolicy`), Office and Windows 11 policies, and the named-pipe
   ACL check (`Get-PipeSecurityDescriptor`).
2. Check that every finding has an Evidence value (CI: 382 of 382).
3. Compare the CIS results with the user's June CIS-CAT scan of this machine, if it's available.
4. Fix what turns up, push, read the CI job summary (`gh run list`, `gh run view <id>`).

Still open afterwards (not urgent): a non-English Windows run (`netsh wlan` parsing is
English-only and reports "not recognized" otherwise); CSV/SARIF export of the whole report;
Pester in CI; a fleet roll-up of JSON exports. Remove this handoff section once it's done.
