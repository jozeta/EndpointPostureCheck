# Changelog

All notable changes to EndpointPostureCheck are listed here, newest first.

The project has no tagged releases yet, so changes are grouped by date. Entries before November 2026 were reconstructed from the commit history.

## Unreleased

- macOS (205 checks): inventories in the dashboard's Inventory section and the JSON export:
  processes (PID, parent, user, CPU, RAM, uptime, binary, signature, listeners, connections,
  launchd label, redacted command line), launchd services (every daemon and agent with status,
  program, signature and writability), network connections, network exposure (each non-loopback
  listener with the application firewall's decision for it), application firewall rules
  (Allow/Block per app), pf rules with anchors, and network filters (system extensions and
  content filter providers). New findings: Privileged Processes Running Writable Binaries,
  Application Firewall Risky App Rules (interpreters, unsigned, stale, replaceable apps), Packet
  Filter (pf) Rules (pass-any, port redirects, non-stock configuration), Network Content
  Filters, Network Exposure Map (unsigned listeners the firewall admits).
- Windows: `-ReportPath` with a folder that does not exist yet and no .html extension now
  creates that folder, as on macOS. It used to become the HTML file name, with the JSON next to it.

- Windows: fixed a parse error that stopped the whole script from running since the
  attack-path batch (`"$pw:"` in the OpenSSH check reads as a drive-qualified variable).
  PSScriptAnalyzer reported the file clean; CI now parses every .ps1 in both Windows PowerShell
  5.1 and PowerShell 7 (`ci/Test-PowerShellParse.ps1`) and runs the full audit, which found it.
- Dashboard (both editions): new Inventory section for structured tables, with tabs, search,
  tag filters, sorting, row details, links between tables and a CSV download of the current
  view. The data is embedded as JSON and rendered with textContent only; the JSON export carries
  the same tables under "Inventory".

- macOS: the "Third-Party Services Listening on the Network" check read the application firewall
  state from `/Library/Preferences/com.apple.alf`, which macOS 15+ no longer uses, so it always
  said "state unknown" and scored Medium. It now asks `socketfilterfw`.
- macOS (199 checks): extended ACLs are now part of every "writable by someone else" test
  (LaunchDaemon/LaunchAgent items and folders, privileged helpers, PAM modules, PATH and dylib
  folders). A root-owned 0644 file with `user:bob allow write` was reported as safe.
- macOS: new "Sudo Rules Allowing Shell Escapes" check. Rules and `Cmnd_Alias` entries that allow
  an editor, pager, interpreter, archiver or copier (GTFOBins) are full root; file readers and
  argument wildcards are a WARN.
- CI runs both audits for real: Windows PowerShell 5.1 and 7 on `windows-latest`, `sudo` on
  `macos-latest`, each a second time with the first run as baseline, validated by
  `ci/Test-ReportOutput.ps1`; the reports are uploaded as build artifacts.

- New attack-path and privilege-escalation checks on both platforms, each in its existing domain.
  - macOS (198 checks): TCC grants to terminals/interpreters or not pinned to a code signature;
    sudo environment (env_reset, env_keep of DYLD_/LD_/PYTHONPATH/..., SETENV) and sudoers file
    ownership; authorization-database admin rights set to allow; PAM integrity (sufficient
    pam_permit, user-writable third-party modules such as a Homebrew pam_reattach); container
    engine sockets and Docker's unauthenticated TCP 2375 API; risky sshd options; third-party
    services listening on the network; secrets in root's and other users' shell/database
    histories (counts only); system-wide DisableLibraryValidation; disabled download quarantine;
    legacy VNC passwords.
  - Windows (161 checks): LocalAccountTokenFilterPolicy and RDP Restricted Admin (pass-the-hash);
    CredSSP delegation to wildcard/NTLM-only targets and the encryption-oracle downgrade; Kerberos
    encryption types (DES/RC4); AMSI provider integrity and AmsiEnable=0; uncommon registry load
    points (AppCertDlls, port monitors, time providers, netsh helpers, password filters, Winlogon
    Notify, BootExecute, SilentProcessExit); service descriptors that let users reconfigure a
    service; WebClient/WebDAV relay exposure; OpenSSH Server options and administrator-key ACLs;
    Point and Print driver installation (PrintNightmare); LM hash storage and DisableDomainCreds.
- Windows: four macOS-parity features (151 checks, 35 domains).
  - `-BaselinePath <earlier.json>`: compares with an earlier `-ExportJson` run. New items in the
    tracked inventories are a scored WARN; controls that got worse or better are reported as INFO.
    Six existing inventories (local administrators, local accounts, WMI subscriptions, Defender
    exclusions, installed applications, inbound firewall rules) now carry item lists for this.
  - Autostart inventory: Run/RunOnce entries (machine and loaded user hives), Startup folders,
    non-Microsoft scheduled tasks and auto-start services outside the Windows folder.
  - Browser extensions (Chrome, Edge, Brave, Vivaldi, Chromium, Firefox, every user): inventory
    plus a risk review with the macOS rules (unpacked, sideloaded, off-store, unsigned, debugger,
    every-site access with cookies/proxy/native messaging). Store update URLs are matched exactly.
    Large Chromium preference files are parsed without Windows PowerShell 5.1's 2 MB JSON limit.
  - PowerShell profile scripts (all-users and per-user, 5.1 and 7, OneDrive-redirected
    Documents): content review for downloads, encoded commands, AMSI/logging or Defender
    tampering, persistence creation and injection APIs, and a FAIL when an all-users profile or
    its folder is writable by non-admins. Plain `Invoke-Expression` is not flagged (prompt tools
    such as oh-my-posh use it).
  - Electron apps whose RunAsNode / NODE_OPTIONS / --inspect fuses are on (a signed-binary
    execution bypass), read by streaming the exe for the fuse wire; at most 25 apps per run.
- Windows dashboard redesigned in the Låda Glass family look, matching the macOS edition: a port
  of the macOS template with identical CSS and JavaScript (sidebar domain filter with FAIL/WARN
  counts, KPI filters, score ring, theme switch, phone card layout, print styles). Long values open
  in the shared popover instead of the old modal. `build.sh` writes the vendored Låda Glass CSS and
  icon sprite into a marked, generated region of the `.ps1`, which stays a single pure-ASCII file.
  The score is formatted with the invariant culture (no "76,3" on a Swedish system).
- Windows: `Add-AuditResult` takes an optional `-Details` item list, shown behind the measured
  value in the dashboard and exported in JSON.
- Dashboard popover (both editions): the pointer can move into it to scroll a long list, and a
  click no longer closes it straight after hover had opened it.
- macOS dashboard sidebar no longer jumps: it scrolls on its own inside the window (it was taller
  than the screen, so the lower domains were out of reach), domain links filter in place instead
  of jumping to `#findings`, the active domain shows as a removable chip above the table, and the
  Overview / System / Findings links mark the current section. The Overview link never worked
  because the page section shared the id `overview` with a Låda Glass sprite icon; renamed.
  "Privilege Escalation: File & Directory Permissions" was split into two sidebar entries by a
  second spelling of the domain name; unified.
- macOS dashboard redesigned in the Låda Glass family look (frosted glass, dark main theme, light
  following the system, theme switch): sidebar with a per-domain FAIL/WARN count that filters the
  table, KPI cards that filter by status, score ring, item lists in a keyboard-accessible popover,
  phone layout without horizontal scrolling, print styles. Låda Glass 1.1.1 is vendored in
  `vendor/lada-glass/` and inlined at build time, so reports stay single offline files.
- **Security (macOS):** a user-controlled value could run commands as root during an audit. The
  screen-lock fallback read `askForPasswordDelay` from the user's own preferences and compared it
  in a zsh arithmetic context, which executes `$(...)` inside an array subscript. Fixed by
  accepting digits only; regression tests use a working exploit payload. (The same pattern in the
  new browser-extension check was caught before release.)
- macOS: XProtect Remediator scan results (7-day unified log): any result other than NoThreatDetected
  is a FAIL, since it means macOS found malware
- macOS: Electron apps whose Node execution fuses are on (RunAsNode, NODE_OPTIONS, `--inspect`),
  which lets local code run inside the app with its privacy permissions (CVE-2025-54871 class)
- macOS: Handoff / Universal Clipboard is now a real check (profile or user setting) instead of a
  "cannot be verified" note
- macOS: `--generate-profile` writes `EndpointPostureCheck-Hardening.mobileconfig` with the compliant
  value of every profile-enforceable WARN/FAIL setting, for review before deploying through an MDM
- macOS: the three slowest queries (login items, Wi-Fi, XProtect log) now run in the background
  while the other checks execute, with a 180 s timeout. A query that started in the background is
  never started a second time (full run on the test Mac: 56 s to 41 s)
- macOS: mSCP rule IDs corrected to real Tahoe rules (24 were not real IDs), and CIS-macOS
  references renumbered to the CIS Apple macOS 26 Tahoe Benchmark v1.0.0
- macOS: fixed a remediation-script bug where a renamed key would have attached the DYLD fix to
  every finding without an mSCP rule
- macOS fixes found while rebuilding the test suite:
  - Root account: an enabled root account (`Password: ********`) was reported as disabled
  - Screen lock: read keys macOS no longer uses, so a Mac that locks immediately got a FAIL; now
    uses `sysadminctl -screenLock status`, with the profile and the old key as fallbacks
  - Firewall: stealth mode always read as "query failed" on Tahoe ("is on/off" wording), and
    "block all" mode (State = 2) was unrecognized
  - SUID/SGID: binaries under `/usr/local` were treated as system files and never reported
  - SSH keys: `known_hosts`, `config` and `authorized_keys` were flagged as readable private keys
  - JSON export: control characters in a finding made the file invalid JSON
  - sudoers and `/etc/hosts`: indented comment lines were treated as active entries
  - Time Machine and NVRAM boot-args: a failed query was reported as "nothing configured"
  - Smaller: "a; b; c" lists, update history picks the newest date regardless of order, sorted
    application lists, case-insensitive iCloud Keychain marker
- macOS fixes from the first real `sudo` run on Tahoe:
  - `--report-path` with a folder that does not exist yet created a file of that name instead of
    the folder
  - SSH server checks always read "not available" (`sshd -T` needs host keys that exist only after
    Remote Login is turned on); now read with `sshd -G`, scored only while Remote Login is on, and
    reported as INFO otherwise
  - Update history failed as root; now read from `/Library/Receipts/InstallHistory.plist`, ignoring
    weekly XProtect data that would make an unpatched Mac look current
  - MRT (retired by Apple) was reported as years out of date; now INFO when XProtect Remediator is
    present
  - Writable PATH listed repeated PATH entries several times

- PSScriptAnalyzer clean-up: checks that fail quietly now say why with `-Verbose`; removed five values
  that were read but never used (including an unused Device Guard query)

- CI: PSScriptAnalyzer on Windows (errors fail, warnings are listed), ShellCheck for `build.sh` and
  a `zsh -n` syntax check of the macOS script

## 2026-11-02

- Add security policy

## 2026-11-01

- Ignore macOS, Claude Code and secret files
- Add CLAUDE.md with project guidance for Claude Code

## 2026-10-28

- macOS: CIS Tahoe v1.0.0 coverage and deep persistence/autostart audit (183 checks)

## 2026-09-14

- Gitignore the built artifact and generated remediation script; verified full end-to-end smoke test
- Document the macOS edition in README: quick start, domains, coverage differences
- Update README: 106 checks (was 98), mention hover-tooltip item lists
- Publish only the built macOS script; untrack src/tests/docs

## 2026-09-10

- Initial commit: existing Windows EndpointPostureCheck tool + macOS port spec/plan
- Ignore .worktrees/ directory
- Add repo scaffold, header/arg-parsing, and test runner for macOS port
