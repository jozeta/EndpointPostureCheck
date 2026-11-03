# Changelog

All notable changes to EndpointPostureCheck are listed here, newest first.

The project has no tagged releases yet, so changes are grouped by date. Entries before November 2026 were reconstructed from the commit history.

## Unreleased

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
