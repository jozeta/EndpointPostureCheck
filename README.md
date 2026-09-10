# EndpointPostureCheck

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

## License

Released under the [MIT License](LICENSE).
