# EndpointPostureCheck

**Comprehensive, standalone, zero-dependency security posture auditors for Windows 11 Enterprise and macOS 15/26 endpoints — one PowerShell, one zsh, no third-party dependencies for either.**

This repository contains two independent tools sharing one design philosophy (fault-isolated checks, weighted compliance scoring, a self-contained HTML dashboard, optional JSON export and generated remediation script):

- [`Invoke-EndpointPostureCheck.ps1`](#endpointposturecheck-for-windows) — Windows 11 Enterprise, 142 checks across 34 domains.
- [`Invoke-MacPostureCheck.sh`](#endpointposturecheck-for-macos) — macOS 15 (Sequoia) / 26 (Tahoe), 98 checks across 30 domains.

---

## EndpointPostureCheck for Windows

**A comprehensive, standalone PowerShell security posture auditor for Windows 11 Enterprise endpoints.**

`EndpointPostureCheck` runs **142 read-only security controls** across 34 hardening domains — from firmware and virtualization-based security through privilege-escalation vectors, AppLocker bypass paths, ransomware resilience, and modern cloud-identity token security — and renders the results as a single-file, interactive HTML dashboard. Every finding is mapped to CIS Controls v8, NIST SP 800-53 Rev.5, MITRE ATT&CK, ISO/IEC 27001:2022, the NIS2 Directive, and NSA/CISA guidance, and the tool can generate a companion remediation script for everything it finds wrong.

It is designed to run standalone with zero external dependencies — no modules to install, no internet access required, just PowerShell and the Windows APIs already on the box.

---

## Contents

- [Highlights](#highlights)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Parameters](#parameters)
- [Output Files](#output-files)
- [Understanding the Report](#understanding-the-report)
- [Audit Domains](#audit-domains)
- [Framework Mappings](#framework-mappings)
- [The Remediation Script](#the-remediation-script)
- [Design Principles](#design-principles)
- [Performance Notes](#performance-notes)
- [Responsible Use](#responsible-use)
- [License](#license)

---

## Highlights

- **142 checks, zero dependencies.** Everything runs on native PowerShell, CIM/WMI, and built-in Windows command-line tools (`bcdedit`, `reagentc`, `vssadmin`, `netsh`, `auditpol`, `wevtutil`, `sc`, `secedit`). Nothing to install.
- **Fault-tolerant by design.** Every single check runs inside its own `try/catch` boundary. A missing subsystem, an unsupported SKU, or an access-denied condition is logged as a `WARN`/`INFO` finding — it never aborts the run.
- **Executive HTML dashboard.** A self-contained, single-file dashboard with a compliance score ring, risk badge, a **System Overview** panel (hostname, domain/Entra ID join state, uptime, IP, disk space, RAM/CPU, installed app count, BitLocker status), and a searchable/filterable findings table.
- **Weighted compliance scoring.** Critical/High severity failures are penalized more heavily than Medium/Low ones; the result is a single 0–100% score and a `LOW`/`MEDIUM`/`HIGH`/`CRITICAL` risk badge.
- **Multi-framework mapping on every finding.** CIS Controls v8, NIST SP 800-53 Rev.5, MITRE ATT&CK technique IDs, ISO/IEC 27001:2022 Annex A, NIS2 Article 21(2), and NSA/CISA guidance.
- **Auto-generated remediation script.** `-GenerateRemediationScript` produces a companion `Remediate-EndpointPostureCheck.ps1` with a commented, `ShouldProcess`-gated block for every `FAIL` finding — real executable commands where it's safe to automate, explicit manual-review guidance where it isn't.
- **JSON export** for feeding results into a SIEM, ticketing system, or a central compliance dashboard.

---

## Requirements

| Requirement | Detail |
|---|---|
| OS | Windows 11 (Enterprise/Education recommended for full AppLocker/WDAC coverage; most checks also run on Pro) |
| PowerShell | 5.1 (Windows PowerShell) or 7.x |
| Privileges | Local Administrator (the script enforces this via `#Requires -RunAsAdministrator` and a redundant runtime check) |
| Modules | None — no `Install-Module` required |
| Network | None required — fully offline-capable |

---

## Quick Start

```powershell
# Run a full audit, write the HTML dashboard to the current directory
.\Invoke-EndpointPostureCheck.ps1

# Full audit + JSON export + auto-generated remediation script, written to a specific folder
.\Invoke-EndpointPostureCheck.ps1 -ReportPath C:\Reports -ExportJson -GenerateRemediationScript
```

The script must be run from an elevated PowerShell session ("Run as Administrator"). If it isn't, it halts immediately with a clear message rather than continuing with a partial, misleading result.

---

## Parameters

| Parameter | Type | Description |
|---|---|---|
| `-ReportPath` | `string` | Optional output location for the HTML dashboard. Accepts a directory (default filename is used) or a full file path. Defaults to the current working directory. |
| `-ExportJson` | `switch` | Exports the complete structured finding set — plus posture/summary metadata — to a JSON file alongside the HTML report. |
| `-GenerateRemediationScript` | `switch` | Generates `Remediate-EndpointPostureCheck.ps1`, containing a remediation block for every `FAIL` finding from the current run. |

---

## Output Files

| File | Description |
|---|---|
| `EndpointPostureCheck_<ComputerName>_<Timestamp>.html` | The interactive dashboard. Always generated. |
| `EndpointPostureCheck_<ComputerName>_<Timestamp>.json` | Full structured export of every finding plus scoring metadata. Generated with `-ExportJson`. |
| `Remediate-EndpointPostureCheck.ps1` | Companion remediation script. Generated with `-GenerateRemediationScript`. Supports `-WhatIf` and requires `-Force` to apply changes. |

---

## Understanding the Report

**Status** — every control resolves to one of:

| Status | Meaning |
|---|---|
| `PASS` | The control meets the recommended configuration. |
| `FAIL` | The control does not meet the recommended configuration and is scored accordingly. |
| `WARN` | A softer finding — a control that's partially met, context-dependent, or an awareness item worth reviewing rather than an outright failure. |
| `INFO` | Contextual/inventory information with no pass-fail judgement (e.g. installed application count, current Wi-Fi SSID). Excluded from scoring. |

**Severity** — `Critical`, `High`, `Medium`, `Low`, or `Informational`. Severity drives both the scoring weight and the color-coded badge in the dashboard.

**Compliance Score** — a weighted percentage: `PASS` earns full credit for a control's severity weight, `WARN` earns half credit, `FAIL` earns none. `INFO`-status findings are excluded entirely. Critical and High severity controls are weighted far more heavily than Low ones, so a handful of critical gaps will visibly move the score even if most controls pass.

**Risk Badge:**

| Badge | Condition |
|---|---|
| `CRITICAL` | Any Critical-severity `FAIL` present |
| `HIGH` | 3+ High-severity `FAIL`s, or score below 60% |
| `MEDIUM` | Score below 80% |
| `LOW` | Otherwise |

The dashboard lets you filter by status (All / Failures Only / Warnings Only / Critical-High Only), filter by category, and free-text search across control names, categories, and remediation guidance.

---

## Audit Domains

142 checks organized across 34 domains:

| # | Domain |
|---|---|
| 1 | Hardware, Firmware & Platform Integrity (TPM, Secure Boot, Kernel DMA Protection) |
| 2 | Virtualization-Based Security & Kernel Isolation (VBS, HVCI, Credential Guard, System Guard, LSA Protection) |
| 3 | Volume Encryption & Data-at-Rest Security (BitLocker status, cipher, key protectors, encryption type) |
| 4 | Next-Gen Antivirus & EDR (Defender real-time/cloud protection, Controlled Folder Access, Network Protection, exclusions, MDE onboarding) |
| 5 | Attack Surface Reduction & Exploit Prevention (ASR rules, DEP/ASLR/CFG/Heap/SEHOP/CET) |
| 6 | Application Control & Software Whitelisting (WDAC, AppLocker baseline, installer security) |
| 7 | Identity, Privilege Management & Access Control (accounts, LAPS, password/lockout policy, UAC) |
| 8 | Network Architecture & Protocol Hardening (firewall, legacy protocols, RDP, SMB, DNS) |
| 9 | Cryptography, Schannel & Secure Channels (TLS/SSL protocol state, cipher suites) |
| 10 | PowerShell Subsystem & Execution Security (logging, execution policy, Constrained Language Mode) |
| 11 | Advanced Security Auditing & Event Logging (audit policy, process-creation command-line logging) |
| 12 | Network Authentication & Credential Exposure Hardening (NTLM, anonymous access, Restrict NTLM) |
| 13 | Privileged Access, User Rights & Session Hardening |
| 14 | Legacy Service Exposure & Remote Management Hardening (Print Spooler, WinRM, Remote Registry) |
| 15 | Removable Media, App Execution & Modern Threat Surface (SmartScreen, Windows Recall base check) |
| 16 | Zero Trust Device Identity, Patch & Time Integrity |
| 17 | Advanced Hardware Mitigations & DNS Security (CET, DNS-over-HTTPS) |
| 18 | Privilege Escalation — Service, File System & DLL Hijacking |
| 19 | Credential Theft & LSASS Exposure |
| 20 | Privileged Token, Process & COM Hijacking |
| 21 | Kernel & Driver Security (vulnerable driver blocklist, test signing, signature validity) |
| 22 | Persistence Mechanisms & Unauthorized Auto-Runs |
| 23 | Active Exploitation & Security Subversion Controls (UAC bypass IOCs, event log ACL tampering) |
| 24 | AppLocker ACL & Bypass Vulnerability Audit (enforcement, writable paths, LOLBAS, registry/service integrity) |
| 25 | Modern Identity, Tokens & Cloud Sync (Entra ID PRT/TPM binding, Seamless SSO, WHfB, Intune/MDM integrity) |
| 26 | Recoverability, Shadow Copies & Ransomware Preparation (VSS, WinRE, System Restore) |
| 27 | Advanced Network Interface, Cellular & Wi-Fi Security |
| 28 | Containerization, WSL & Hyper-V Escape Vectors |
| 29 | Insecure Temporary Files, Unattended Scripts & Secret Leaks (SSH keys, AWS/Azure CLI, PSReadLine history) |
| 30 | Peripheral, Thunderbolt & Media Controls |
| 31 | Artificial Intelligence & Telemetry Hardening (Copilot, Recall, diagnostic data level) |
| 32 | Targeted Gap Checks — Defender, Network, Accounts & Awareness |
| 33 | Targeted Gap Closure — Credential, Kernel, Network & Privacy |
| 34 | System Inventory & Asset Information |

---

## Framework Mappings

Every finding carries mappings to:

- **CIS Controls v8** (Safeguard IDs)
- **NIST SP 800-53 Rev.5** control families
- **MITRE ATT&CK** technique IDs (v14+)
- **ISO/IEC 27001:2022** Annex A controls
- **NIS2 Directive** Article 21(2) risk-management measures
- **NSA/CISA** hardening guidance references

These are provided as a practical starting point for compliance documentation and threat-modeling context. They are not a substitute for a formal compliance assessment against the authoritative source documents.

---

## The Remediation Script

`Remediate-EndpointPostureCheck.ps1` is generated from the **current run's** `FAIL` findings only, grouped by category and sorted by severity. Each block includes the original finding's severity, current/expected value, and framework mappings as comments, followed by:

- **Real, executable commands** where automated remediation is safe and unambiguous (e.g. registry hardening values, service state changes, `Set-MpPreference` calls).
- **Explicit manual-guidance warnings** where blind automation would be risky — Active Directory/local group membership changes, User Rights Assignment edits, AppLocker/WDAC policy authoring, and anything flagged as a possible active compromise indicator (which also instructs you to capture forensic evidence *before* remediating).

The script supports `-WhatIf` for a dry run and requires `-Force` to actually apply changes — nothing executes by accident. **Always review the generated script before running it in production**, and pilot it on a representative device before broad deployment.

---

## Design Principles

A few choices worth knowing about if you're extending this tool:

- **Honesty over false precision.** Where Windows doesn't expose a clean, reliable API for something (exact Secure Boot certificate expiration, precise WSL/MDE sensor integration state, CPU mitigation bitmask semantics), the corresponding check says so explicitly and points to the authoritative manual-verification path, rather than asserting a judgement it can't actually back up.
- **Defaults aren't automatically findings.** Several checks (`SeImpersonatePrivilege` assignment, UAC installer detection, Windows Copilot policy) deliberately avoid flagging normal Windows-default or environment-dependent behavior as a misconfiguration — the goal is a low-noise, accurate report, not maximum finding count.
- **No duplicate/contradictory checks.** Where two possible checks would evaluate the same underlying setting with different thresholds, only one was kept, to avoid the report disagreeing with itself.
- **Performance-bounded scans.** File/log searches (developer secret sweep, third-party agent secret scan) are capped to the most relevant/recent files rather than recursing entire directory trees.

---

## Performance Notes

A full run typically takes **60–90 seconds** depending on hardware and installed feature set (WSL, Hyper-V, AppLocker, and Wi-Fi profile checks each add a few seconds). All 142 checks run sequentially in a single process for fault-tolerance and predictable console output ordering.

---

## Responsible Use

This tool includes deep-inspection checks — LSASS/credential exposure, ACL/privilege-escalation vectors, AppLocker bypass surfaces, GPP/SSH/cloud-CLI secret discovery — of the same kind used by tools such as WinPEAS, Seatbelt, and PowerUp. These are **defensive, read-only audit checks** intended to help you find and fix your own weaknesses before someone else does.

- Run this only against systems you own or are explicitly authorized to assess.
- Findings in categories like *Credential Exposure & Secret Leaks* and *Privilege Escalation* can surface sensitive material (file paths, partial credential indicators, registry contents). Treat the generated HTML/JSON reports as sensitive documents and store/share them accordingly.
- The tool performs no exploitation, no credential extraction, and no modification to the target system during an audit run — the only file it writes (besides its own reports) is the optional remediation script, which itself does not execute automatically.

---

## EndpointPostureCheck for macOS

**A comprehensive, standalone zsh security posture auditor for macOS 15 (Sequoia) and 26 (Tahoe) endpoints.**

`Invoke-MacPostureCheck.sh` runs **98 read-only security controls** across 30 hardening domains — from Secure Enclave/T2 platform integrity and System Integrity Protection through Gatekeeper, TCC privacy controls, FileVault, credential exposure, and ransomware resilience — and renders the results as a single-file, interactive HTML dashboard, in the same visual language as the Windows edition. Every finding is mapped to CIS Controls v8, NIST SP 800-53 Rev.5, MITRE ATT&CK, ISO/IEC 27001:2022, the NIS2 Directive, NSA/CISA guidance, the CIS Apple macOS Benchmark, and the macOS Security Compliance Project (mSCP) — two mappings the Windows edition doesn't carry, since they're macOS-specific authoritative baselines.

It runs standalone with zero external dependencies: no Homebrew packages, no Python, nothing beyond the zsh shell and command-line tools Apple ships on every Mac.

### Requirements

| Requirement | Detail |
|---|---|
| OS | macOS 15 (Sequoia) or macOS 26 (Tahoe). Older versions still run, with one WARN finding noting results may be incomplete. |
| Shell | zsh (the default interactive shell on macOS since Catalina; bash's stock macOS build is too old — 3.2 — for this tool's needs) |
| Privileges | root (the script enforces this at startup and exits immediately if not run via `sudo`, matching the Windows edition's `#Requires -RunAsAdministrator`) |
| Hardware | Apple Silicon and Intel both supported. Checks specific to one architecture (Secure Enclave boot-policy checks on Apple Silicon; T2/firmware-password checks on Intel) report `INFO` "not applicable" on the other rather than a false result. |
| Dependencies | None — no `brew install` required |
| Network | None required — every check is offline-capable, including patch-compliance checks (which read local `softwareupdate --history`, never trigger a live `-l` network scan) |

### Quick Start

```bash
# Run a full audit, write the HTML dashboard to the current directory
sudo ./Invoke-MacPostureCheck.sh

# Full audit + JSON export + generated remediation script, written to a specific folder
sudo ./Invoke-MacPostureCheck.sh --report-path ~/Reports --export-json --generate-remediation
```

The script must be run with `sudo`. If it isn't, it exits immediately with a clear message rather than continuing with a partial, misleading result — checks that need a specific console user's preferences (screen lock, Safari settings, iCloud/AirDrop state, etc.) are still read correctly under `sudo` by dropping to that user for just those reads, not by running the whole audit unprivileged.

### Parameters

| Parameter | Description |
|---|---|
| `--report-path <dir\|file>` | Optional output location for the HTML dashboard. Accepts a directory (default filename is used) or a full file path. Defaults to the current working directory. |
| `--export-json` | Exports the complete structured finding set, plus posture/summary metadata, to a JSON file alongside the HTML report. |
| `--generate-remediation` | Generates `Remediate-EndpointPostureCheck.sh`, containing a remediation block for every `FAIL` finding from the current run. |
| `--help` | Show usage and exit. |

### Output Files

Same three-file pattern as the Windows edition: `EndpointPostureCheck_<hostname>_<timestamp>.html` (always generated), `EndpointPostureCheck_<hostname>_<timestamp>.json` (with `--export-json`), `Remediate-EndpointPostureCheck.sh` (with `--generate-remediation`, supports `--dry-run`/`--force`, defaults to preview-only).

### Understanding the Report

Identical `PASS`/`FAIL`/`WARN`/`INFO` status semantics, `Critical`/`High`/`Medium`/`Low`/`Informational` severity levels, weighted compliance scoring (severity weights `Critical=10, High=7, Medium=4, Low=2`; `PASS` full credit, `WARN` half credit, `FAIL` none; `INFO` excluded entirely), and `LOW`/`MEDIUM`/`HIGH`/`CRITICAL` risk badge thresholds as the Windows edition — see that section above for the full breakdown; the scoring engine is a direct, verified port.

### Audit Domains

98 checks organized across 30 domains:

| # | Domain |
|---|---|
| 1 | Hardware, Firmware & Platform Integrity (Secure Enclave / T2) |
| 2 | SIP & Kernel Security |
| 3 | Volume Encryption & Data-at-Rest (FileVault) |
| 4 | Gatekeeper, Notarization & Application Control |
| 5 | Malware Defense (XProtect / MRT / EDR) |
| 6 | TCC & Privacy Controls |
| 7 | Identity, Accounts & Privilege Management |
| 8 | Network Firewall & Packet Filtering |
| 9 | Remote Access & Sharing Services |
| 10 | SSH Server & Client Hardening |
| 11 | Cryptography & Certificate Trust |
| 12 | Audit, Logging & Telemetry |
| 13 | Software Update & Patch Compliance |
| 14 | MDM, Profiles & Supervision |
| 15 | Persistence Mechanisms & Auto-Runs |
| 16 | Privilege Escalation — File & Directory Permissions |
| 17 | Dylib Hijacking & Code Injection |
| 18 | Credential Exposure & Secret Leaks |
| 19 | Screen Lock & Physical Access |
| 20 | Removable Media & Peripheral Control |
| 21 | Wireless & Network Interface Security |
| 22 | iCloud & Cloud Sync Surface |
| 23 | Browser & Application Hardening |
| 24 | Ransomware Resilience & Recovery |
| 25 | Third-Party Software & Package Inventory |
| 26 | System Services & Daemon Exposure |
| 27 | Kernel & Boot Security |
| 28 | Virtualization & Container Escape Surface |
| 29 | Data Loss Prevention & Sensitive Data |
| 30 | System Inventory & Asset Information |

### What Didn't Port, and What's New

The two platforms don't share a threat surface one-for-one. Dropped
entirely (no macOS equivalent): VBS/HVCI/Credential Guard/System Guard,
BitLocker specifics (replaced wholesale by the FileVault domain), ASR
rules, WDAC/AppLocker's 11-check module (replaced by the 6-check
Gatekeeper/notarization domain), LAPS, UAC-specific checks (folded into
`sudoers`/authorization-adjacent identity checks), Schannel registry
policy, PowerShell subsystem security, Print Spooler, WPAD/LLMNR/NetBIOS,
COM CLSID hijacking, IFEO, AppInit_DLLs, WSL/Hyper-V/Windows
Sandbox/WDAG, Windows Recall/Copilot. Added, with no Windows counterpart:
TCC & Privacy Controls (Domain 6), iCloud & Cloud Sync Surface (Domain
22), Browser & Application Hardening (Domain 23), Data Loss Prevention &
Sensitive Data (Domain 29), and Dylib Hijacking & Code Injection (Domain
17, the closest macOS analogue to DLL hijacking but a genuinely different
mechanism).

### Framework Mappings

The same six frameworks as the Windows edition (CIS Controls v8, NIST SP
800-53 Rev.5, MITRE ATT&CK, ISO/IEC 27001:2022, NIS2 Article 21(2),
NSA/CISA guidance), plus two macOS-specific mappings: **CIS Apple macOS
Benchmark** section references and **macOS Security Compliance Project
(mSCP)** rule IDs — the authoritative macOS hardening baselines,
maintained by NIST/NASA/DoD for mSCP, that a macOS-focused auditor is
most likely to be asked for directly.

### Design Principles

Same three principles as the Windows edition, carried over deliberately: **honesty over false precision** (several macOS checks — Time Machine backup encryption state, Handoff/Universal Clipboard exposure, FIPS crypto-module validation — say so explicitly rather than guessing, where macOS exposes no clean, documented CLI signal); **no duplicate/contradictory checks** (a few candidate checks were cut during design specifically to avoid two checks silently disagreeing about the same underlying setting); **performance-bounded scans** (shell-history and sensitive-filename sweeps are capped to recent/top-level content, never a full recursive disk walk).

---

## License

Released under the [MIT License](LICENSE).
