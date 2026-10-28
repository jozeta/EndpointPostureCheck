#!/usr/bin/env zsh
# EndpointPostureCheck for macOS — built 2026-10-28 11:03:32 from src/*.zsh. Do not edit directly.

# ---- 00-header.zsh ----
#
# EndpointPostureCheck for macOS
# A read-only security posture auditor for macOS 15/26 endpoints.
#
# Usage: Invoke-MacPostureCheck.sh [--report-path <dir|file>] [--export-json]
#                                   [--generate-remediation] [--help]
#
# Deliberately NOT running under `set -u`/`set -e`: the #1 design
# requirement (Global Constraints) is that one check's failure must never
# abort the run. Unlike PowerShell, plain zsh without `set -e` already
# treats a failing command as non-fatal per-statement by default, which is
# exactly the fault-tolerance the original tool's try/catch-per-check
# achieved — so this port doesn't need an equivalent wrapper construct, it
# just needs to avoid opting INTO strict/exit-on-error modes for the
# shipped script. Individual `tests/test-*.zsh` files still use `set -u`
# themselves, since catching an unbound-variable bug loudly during
# development is exactly when you want it to be fatal.
setopt PIPE_FAIL

SCRIPT_VERSION="1.0.0"
SCRIPT_NAME="EndpointPostureCheck"
START_TIME_EPOCH=$(date +%s)
START_TIME_HUMAN=$(date '+%Y-%m-%d %H:%M:%S')
COMPUTER_NAME=$(scutil --get ComputerName 2>/dev/null || hostname)

REPORT_PATH=""
EXPORT_JSON=0
GENERATE_REMEDIATION=0

print_usage() {
    cat <<'EOF'
EndpointPostureCheck for macOS

Usage:
  Invoke-MacPostureCheck.sh [options]

Options:
  --report-path <dir|file>   Output location for the HTML dashboard.
                              Accepts a directory (default filename used)
                              or a full file path. Defaults to the current
                              working directory.
  --export-json               Export the complete finding set to JSON
                               alongside the HTML report.
  --generate-remediation       Generate Remediate-EndpointPostureCheck.sh
                               for every FAIL finding from this run.
  --help                       Show this help text and exit.

Must be run with sudo (root). No changes are made to the system during
an audit run.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --report-path)
            if [[ $# -lt 2 ]]; then
                echo "Error: --report-path requires a value" >&2
                exit 1
            fi
            REPORT_PATH="$2"
            shift 2
            ;;
        --export-json)
            EXPORT_JSON=1
            shift
            ;;
        --generate-remediation)
            GENERATE_REMEDIATION=1
            shift
            ;;
        --help|-h)
            print_usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            print_usage
            exit 1
            ;;
    esac
done

# --- Elevation gate (mirrors #Requires -RunAsAdministrator in the Windows tool) ---
if [[ "$(id -u)" -ne 0 ]]; then
    echo ""
    echo "================================================================================="
    echo "  EndpointPostureCheck requires root privileges to run."
    echo "  Please re-run with: sudo ./Invoke-MacPostureCheck.sh"
    echo "================================================================================="
    echo ""
    exit 1
fi

# --- Console user detection, for checks that must read a per-user preference domain ---
CONSOLE_USER=$(stat -f%Su /dev/console 2>/dev/null || echo "")
if [[ -z "$CONSOLE_USER" || "$CONSOLE_USER" == "root" ]]; then
    CONSOLE_USER=$(who | awk '$2=="console"{print $1; exit}')
fi
CONSOLE_USER_UID=""
if [[ -n "$CONSOLE_USER" ]]; then
    CONSOLE_USER_UID=$(id -u "$CONSOLE_USER" 2>/dev/null || echo "")
fi

IS_APPLE_SILICON=0
if [[ "$(uname -m)" == "arm64" ]]; then
    IS_APPLE_SILICON=1
fi

OS_PRODUCT_VERSION=$(sw_vers -productVersion 2>/dev/null || echo "0.0")
OS_BUILD=$(sw_vers -buildVersion 2>/dev/null || echo "Unknown")

# ---- 01-core.zsh ----
#
# EndpointPostureCheck for macOS — core helpers.
# Sourceable independently of 00-header.zsh: defensively defaults every
# external variable it reads, so tests/test-core.zsh can source this file
# alone without triggering the root gate or CLI arg parsing.

: ${CONSOLE_USER:=""}
: ${IS_APPLE_SILICON:=0}
: ${OS_PRODUCT_VERSION:="0.0"}

typeset -ga AUDIT_IDS=()
typeset -ga AUDIT_CATEGORY=()
typeset -ga AUDIT_CONTROL=()
typeset -ga AUDIT_STATUS=()
typeset -ga AUDIT_SEVERITY=()
typeset -ga AUDIT_CURRENT=()
typeset -ga AUDIT_DETAILS=()
typeset -ga AUDIT_RECOMMENDED=()
typeset -ga AUDIT_CIS=()
typeset -ga AUDIT_NIST=()
typeset -ga AUDIT_MITRE=()
typeset -ga AUDIT_ISO27001=()
typeset -ga AUDIT_NIS2=()
typeset -ga AUDIT_NSA=()
typeset -ga AUDIT_CISMACOS=()
typeset -ga AUDIT_MSCP=()
typeset -ga AUDIT_RECOMMENDATION=()
typeset -ga AUDIT_TIMESTAMP=()

reset_audit_results() {
    AUDIT_IDS=() AUDIT_CATEGORY=() AUDIT_CONTROL=() AUDIT_STATUS=() AUDIT_SEVERITY=()
    AUDIT_CURRENT=() AUDIT_DETAILS=() AUDIT_RECOMMENDED=() AUDIT_CIS=() AUDIT_NIST=() AUDIT_MITRE=()
    AUDIT_ISO27001=() AUDIT_NIS2=() AUDIT_NSA=() AUDIT_CISMACOS=() AUDIT_MSCP=()
    AUDIT_RECOMMENDATION=() AUDIT_TIMESTAMP=()
}

add_audit_result() {
    local category="" control="" status_val="" severity=""
    local current_value="N/A" recommended_value="N/A"
    # details_value is optional and empty by default (not "N/A" — an
    # empty string is the signal the HTML renderer uses to skip the
    # hover-tooltip wrapper entirely for findings with nothing to list).
    local details_value=""
    local cis="N/A" nist="N/A" mitre="N/A" iso27001="N/A" nis2="N/A" nsa="N/A"
    local cis_macos="N/A" mscp="N/A"
    local recommendation="No remediation required."

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --category) category="$2"; shift 2 ;;
            --control) control="$2"; shift 2 ;;
            --status) status_val="$2"; shift 2 ;;
            --severity) severity="$2"; shift 2 ;;
            --current) current_value="$2"; shift 2 ;;
            --details) details_value="$2"; shift 2 ;;
            --recommended) recommended_value="$2"; shift 2 ;;
            --cis) cis="$2"; shift 2 ;;
            --nist) nist="$2"; shift 2 ;;
            --mitre) mitre="$2"; shift 2 ;;
            --iso27001) iso27001="$2"; shift 2 ;;
            --nis2) nis2="$2"; shift 2 ;;
            --nsa) nsa="$2"; shift 2 ;;
            --cis-macos) cis_macos="$2"; shift 2 ;;
            --mscp) mscp="$2"; shift 2 ;;
            --recommendation) recommendation="$2"; shift 2 ;;
            *) echo "add_audit_result: unknown argument: $1" >&2; shift ;;
        esac
    done

    if [[ -z "$category" || -z "$control" || -z "$status_val" || -z "$severity" ]]; then
        echo "add_audit_result: --category, --control, --status and --severity are required" >&2
        return 1
    fi

    case "$status_val" in
        PASS|FAIL|WARN|INFO) ;;
        *) echo "add_audit_result: invalid --status '$status_val'" >&2; return 1 ;;
    esac
    case "$severity" in
        Critical|High|Medium|Low|Informational) ;;
        *) echo "add_audit_result: invalid --severity '$severity'" >&2; return 1 ;;
    esac

    local next_id=$(( ${#AUDIT_STATUS[@]} + 1 ))

    AUDIT_IDS+=("$next_id")
    AUDIT_CATEGORY+=("$category")
    AUDIT_CONTROL+=("$control")
    AUDIT_STATUS+=("$status_val")
    AUDIT_SEVERITY+=("$severity")
    AUDIT_CURRENT+=("$current_value")
    AUDIT_DETAILS+=("$details_value")
    AUDIT_RECOMMENDED+=("$recommended_value")
    AUDIT_CIS+=("$cis")
    AUDIT_NIST+=("$nist")
    AUDIT_MITRE+=("$mitre")
    AUDIT_ISO27001+=("$iso27001")
    AUDIT_NIS2+=("$nis2")
    AUDIT_NSA+=("$nsa")
    AUDIT_CISMACOS+=("$cis_macos")
    AUDIT_MSCP+=("$mscp")
    AUDIT_RECOMMENDATION+=("$recommendation")
    AUDIT_TIMESTAMP+=("$(date '+%Y-%m-%d %H:%M:%S')")

    local color="" reset=$'\033[0m'
    case "$status_val" in
        PASS) color=$'\033[32m' ;;
        FAIL) color=$'\033[31m' ;;
        WARN) color=$'\033[33m' ;;
        INFO) color=$'\033[36m' ;;
    esac
    printf "  %s[%-4s] (%-8s) %s%s\n" "$color" "$status_val" "$severity" "$control" "$reset"
    return 0
}

run_root() {
    ROOT_CMD_OUTPUT=$("$@" 2>&1)
    ROOT_CMD_STATUS=$?
    return 0
}

run_as_user() {
    if [[ -z "$CONSOLE_USER" ]]; then
        RUN_AS_USER_OUTPUT="No console user detected"
        RUN_AS_USER_STATUS=127
        return 0
    fi
    RUN_AS_USER_OUTPUT=$(sudo -u "$CONSOLE_USER" "$@" 2>&1)
    RUN_AS_USER_STATUS=$?
    return 0
}

defaults_read_safe() {
    local domain="$1" key="$2" default_value="${3:-}"
    local value
    value=$(defaults read "$domain" "$key" 2>/dev/null)
    if [[ $? -ne 0 || -z "$value" ]]; then
        printf '%s' "$default_value"
        return 1
    fi
    printf '%s' "$value"
    return 0
}

defaults_read_as_user_safe() {
    local domain="$1" key="$2" default_value="${3:-}"
    if [[ -z "$CONSOLE_USER" ]]; then
        printf '%s' "$default_value"
        return 1
    fi
    local value
    value=$(sudo -u "$CONSOLE_USER" defaults read "$domain" "$key" 2>/dev/null)
    if [[ $? -ne 0 || -z "$value" ]]; then
        printf '%s' "$default_value"
        return 1
    fi
    printf '%s' "$value"
    return 0
}

plist_value_safe() {
    # Named "plist_path", not "path": zsh ties the scalar $PATH to the
    # array $path, and a plain "local path=..." here would shadow that
    # array for this call's entire dynamic scope, breaking bare-name
    # external-command lookup for anything called during it (this
    # function's own PlistBuddy call is unaffected since it's invoked by
    # absolute path, but any bare-name command run downstream while this
    # function is still on the stack would silently fail).
    local plist_path="$1" keypath="$2" default_value="${3:-}"
    if [[ ! -f "$plist_path" ]]; then
        printf '%s' "$default_value"
        return 1
    fi
    local value
    value=$(/usr/libexec/PlistBuddy -c "Print :$keypath" "$plist_path" 2>/dev/null)
    if [[ $? -ne 0 ]]; then
        printf '%s' "$default_value"
        return 1
    fi
    printf '%s' "$value"
    return 0
}

sqlite_value_safe() {
    local db="$1" query="$2" default_value="${3:-}"
    if [[ ! -f "$db" ]]; then
        printf '%s' "$default_value"
        return 1
    fi
    local value
    value=$(sqlite3 "$db" "$query" 2>/dev/null)
    if [[ $? -ne 0 ]]; then
        printf '%s' "$default_value"
        return 1
    fi
    printf '%s' "$value"
    return 0
}

macos_version_ge() {
    local required="$1"
    local current="${2:-$OS_PRODUCT_VERSION}"
    local -a req_parts cur_parts
    req_parts=("${(@s/./)required}")
    cur_parts=("${(@s/./)current}")
    local i r c
    for i in 1 2 3; do
        r=${req_parts[$i]:-0}
        c=${cur_parts[$i]:-0}
        if (( c > r )); then return 0; fi
        if (( c < r )); then return 1; fi
    done
    return 0
}

is_apple_silicon() {
    [[ "$IS_APPLE_SILICON" -eq 1 ]]
}

write_section_banner() {
    local title="$1"
    local rule
    rule=$(printf '=%.0s' {1..78})
    printf "\n%s\n" "$rule"
    printf " %s\n" "$title"
    printf "%s\n" "$rule"
}

# Reads a preference the way the CIS Apple macOS Benchmark audits it:
# through NSUserDefaults (via JXA), as root. Unlike a plain
# `defaults read /Library/Preferences/<domain>`, NSUserDefaults also
# resolves keys forced by an MDM configuration profile (/Library/Managed
# Preferences), which is where most CIS "Ensure ... Is Disabled" settings
# live — reading only the on-disk plist would report a profile-enforced
# setting as unset. Booleans are normalized to 1/0.
# Returns 0 = key set (value printed), 1 = key not set anywhere,
# 2 = the osascript query itself failed (never conflated with "unset").
managed_pref_read() {
    local suite="$1" key="$2" value
    value=$(osascript -l JavaScript -e "var v = \$.NSUserDefaults.alloc.initWithSuiteName('$suite').objectForKey('$key'); v.isNil() ? '' : String(ObjC.deepUnwrap(v))" 2>/dev/null)
    if [[ $? -ne 0 ]]; then
        return 2
    fi
    case "$value" in
        true) value=1 ;;
        false) value=0 ;;
    esac
    if [[ -z "$value" ]]; then
        return 1
    fi
    printf '%s' "$value"
    return 0
}

# Shared evaluator for CIS recommendations that audit one managed
# preference key. Comparison is --expect <value> (exact match) or
# --min/--max <n> (integer range, either or both).
#
# Scoring policy for an UNSET key, agreed with the project owner: WARN
# ("not enforced by a configuration profile"), never FAIL. An unmanaged
# Mac hasn't chosen an insecure value, it just hasn't been hardened —
# and ~25 profile-only CIS controls would otherwise swamp the score on
# every personal Mac. An explicitly insecure value is still a FAIL.
# --unset-ok is for keys whose CIS audit itself passes when unset (e.g.
# software-update deferral: "no output ... will pass the audit").
evaluate_managed_pref() {
    local category="" control="" severity="" suite="" key=""
    local expect="" min="" max="" unset_ok=0 recommendation=""
    local -a fw
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --category) category="$2"; shift 2 ;;
            --control) control="$2"; shift 2 ;;
            --severity) severity="$2"; shift 2 ;;
            --suite) suite="$2"; shift 2 ;;
            --key) key="$2"; shift 2 ;;
            --expect) expect="$2"; shift 2 ;;
            --min) min="$2"; shift 2 ;;
            --max) max="$2"; shift 2 ;;
            --unset-ok) unset_ok=1; shift ;;
            --recommendation) recommendation="$2"; shift 2 ;;
            --cis|--nist|--mitre|--iso27001|--nis2|--nsa|--cis-macos|--mscp) fw+=("$1" "$2"); shift 2 ;;
            *) echo "evaluate_managed_pref: unknown argument: $1" >&2; shift ;;
        esac
    done

    local recommended
    if [[ -n "$expect" ]]; then
        recommended="$key = $expect"
    elif [[ -n "$min" && -n "$max" ]]; then
        recommended="$min <= $key <= $max"
    elif [[ -n "$max" ]]; then
        recommended="$key <= $max"
    else
        recommended="$key >= $min"
    fi

    local -a base
    base=(--category "$category" --control "$control" --recommended "$recommended" "${fw[@]}")

    local value rc
    value=$(managed_pref_read "$suite" "$key")
    rc=$?

    if [[ $rc -eq 2 ]]; then
        add_audit_result "${base[@]}" --status WARN --severity Low \
            --current "Preference query failed for $suite / $key" \
            --recommendation "Unable to read $suite / $key via NSUserDefaults; verify the setting manually."
        return 0
    fi

    if [[ $rc -eq 1 ]]; then
        if [[ $unset_ok -eq 1 ]]; then
            add_audit_result "${base[@]}" --status PASS --severity "$severity" \
                --current "$key not set (CIS treats unset as compliant)" \
                --recommendation 'No action required.'
        else
            add_audit_result "${base[@]}" --status WARN --severity "$severity" \
                --current "$key not set - not enforced by a configuration profile" \
                --recommendation "$recommendation"
        fi
        return 0
    fi

    local ok=0
    if [[ -n "$expect" ]]; then
        [[ "$value" == "$expect" ]] && ok=1
    elif [[ "$value" == <-> ]]; then
        ok=1
        [[ -n "$min" ]] && (( value < min )) && ok=0
        [[ -n "$max" ]] && (( value > max )) && ok=0
    fi

    if [[ $ok -eq 1 ]]; then
        add_audit_result "${base[@]}" --status PASS --severity "$severity" \
            --current "$suite / $key = $value" --recommendation 'No action required.'
    else
        add_audit_result "${base[@]}" --status FAIL --severity "$severity" \
            --current "$suite / $key = $value" --recommendation "$recommendation"
    fi
}

# Installed-configuration-profile payload dump, cached for the run:
# system_profiler takes ~1s and several CIS controls (Safari, hot
# corners) read it. Must be primed by a direct call, not inside $(...),
# or the cache assignment is lost with the subshell.
typeset -g CONFIG_PROFILE_DUMP=""
typeset -gi CONFIG_PROFILE_DUMP_STATUS=-1

load_config_profile_dump() {
    if [[ $CONFIG_PROFILE_DUMP_STATUS -lt 0 ]]; then
        CONFIG_PROFILE_DUMP=$(system_profiler SPConfigurationProfileDataType 2>&1)
        CONFIG_PROFILE_DUMP_STATUS=$?
    fi
    return $CONFIG_PROFILE_DUMP_STATUS
}

# Prints the value of a payload key from the cached profile dump
# ('    "Key.Name" = 1;' -> '1'); returns 1 when no installed profile sets it.
config_profile_value() {
    local key="$1" line
    line=$(print -r -- "$CONFIG_PROFILE_DUMP" | tr -d ' \t"' | grep -E "^${key//./\\.}=" | head -1)
    [[ -z "$line" ]] && return 1
    line="${line#*=}"
    printf '%s' "${line%;}"
    return 0
}

# Shared evaluator for profile-only CIS controls verified against the
# installed-profile dump (the CIS audit method for Safari settings).
# Every --pair Key=Value must be present and match to PASS; any present
# with a different value is a FAIL; none present is a WARN (same unset
# policy as evaluate_managed_pref).
evaluate_profile_payload() {
    local category="" control="" severity="" recommendation=""
    local -a pairs fw
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --category) category="$2"; shift 2 ;;
            --control) control="$2"; shift 2 ;;
            --severity) severity="$2"; shift 2 ;;
            --pair) pairs+=("$2"); shift 2 ;;
            --recommendation) recommendation="$2"; shift 2 ;;
            --cis|--nist|--mitre|--iso27001|--nis2|--nsa|--cis-macos|--mscp) fw+=("$1" "$2"); shift 2 ;;
            *) echo "evaluate_profile_payload: unknown argument: $1" >&2; shift ;;
        esac
    done

    local -a base
    base=(--category "$category" --control "$control" --recommended "${(j:, :)pairs}" "${fw[@]}")

    if ! load_config_profile_dump; then
        add_audit_result "${base[@]}" --status WARN --severity Low \
            --current "Configuration profile query failed: $CONFIG_PROFILE_DUMP" \
            --recommendation 'Unable to list installed configuration profiles; verify manually in System Settings > General > Device Management.'
        return 0
    fi

    local pair want got found=0 mismatch=0
    local -a seen
    for pair in "${pairs[@]}"; do
        want="${pair#*=}"
        got=$(config_profile_value "${pair%%=*}") || { seen+=("${pair%%=*} not set"); continue; }
        found=$((found + 1))
        seen+=("${pair%%=*}=$got")
        [[ "$got" != "$want" ]] && mismatch=1
    done

    if [[ $mismatch -eq 1 ]]; then
        add_audit_result "${base[@]}" --status FAIL --severity "$severity" \
            --current "${(j:, :)seen}" --recommendation "$recommendation"
    elif [[ $found -eq ${#pairs[@]} ]]; then
        add_audit_result "${base[@]}" --status PASS --severity "$severity" \
            --current "${(j:, :)seen}" --recommendation 'No action required.'
    else
        add_audit_result "${base[@]}" --status WARN --severity "$severity" \
            --current "${(j:, :)seen} - not fully enforced by a configuration profile" \
            --recommendation "$recommendation"
    fi
}

# ---- 10-hardware.zsh ----
#
# Domain 1: Hardware, Firmware & Platform Integrity

check_secure_enclave_presence() {
    write_section_banner 'Hardware, Firmware & Platform Integrity - Secure Enclave / T2'

    if is_apple_silicon; then
        run_root ioreg -c AppleSEPManager
        if [[ "$ROOT_CMD_OUTPUT" == *"AppleSEPManager"* ]]; then
            add_audit_result --category 'Hardware, Firmware & Platform Integrity' \
                --control 'Secure Enclave Presence' --status PASS --severity Critical \
                --current 'Secure Enclave (SEP) detected via ioreg' --recommended 'Secure Enclave present' \
                --cis 'CIS 10.5' --nist 'IA-3, SC-28' --mitre 'T1552.004' --iso27001 'A.8.24' \
                --nis2 'Art.21(2)(h)' --nsa 'NSA/CISA Advancing Zero Trust Maturity - Device Pillar' \
                --cis-macos 'CIS-macOS 1.1' --mscp 'os_secure_enclave_present' \
                --recommendation 'No action required. Every Apple Silicon Mac ships with a Secure Enclave.'
        else
            add_audit_result --category 'Hardware, Firmware & Platform Integrity' \
                --control 'Secure Enclave Presence' --status WARN --severity Medium \
                --current 'Secure Enclave not detected via ioreg' --recommended 'Secure Enclave present' \
                --cis 'CIS 10.5' --nist 'IA-3, SC-28' --cis-macos 'CIS-macOS 1.1' --mscp 'os_secure_enclave_present' \
                --recommendation 'Unexpected on Apple Silicon hardware. Verify with "system_profiler SPiBridgeDataType" and Apple Diagnostics; this may indicate a query failure rather than a real absence.'
        fi
    else
        run_root system_profiler SPiBridgeDataType
        if [[ "$ROOT_CMD_OUTPUT" == *"Apple T2"* ]]; then
            add_audit_result --category 'Hardware, Firmware & Platform Integrity' \
                --control 'Secure Enclave Presence' --status PASS --severity High \
                --current 'Apple T2 Security Chip detected' --recommended 'T2 Security Chip present' \
                --cis 'CIS 10.5' --nist 'IA-3, SC-28' --cis-macos 'CIS-macOS 1.1' --mscp 'os_secure_enclave_present' \
                --recommendation 'No action required.'
        else
            add_audit_result --category 'Hardware, Firmware & Platform Integrity' \
                --control 'Secure Enclave Presence' --status WARN --severity High \
                --current 'No T2 Security Chip detected' --recommended 'T2 Security Chip present' \
                --cis 'CIS 10.5' --nist 'IA-3, SC-28' --cis-macos 'CIS-macOS 1.1' --mscp 'os_secure_enclave_present' \
                --recommendation 'This Intel Mac has no T2 chip: no hardware root of trust, no local Secure Boot, no hardware-bound key storage. Prioritize this device for hardware refresh where BitLocker/FileVault-equivalent guarantees matter.'
        fi
    fi
}

check_hardware_identification() {
    run_root system_profiler SPHardwareDataType
    local model chip serial
    model=$(print -r -- "$ROOT_CMD_OUTPUT" | awk -F': ' '/Model Name/{print $2; exit}')
    chip=$(print -r -- "$ROOT_CMD_OUTPUT" | awk -F': ' '/^ *Chip:|Processor Name/{print $2; exit}')
    serial=$(print -r -- "$ROOT_CMD_OUTPUT" | awk -F': ' '/Serial Number/{print $2; exit}')
    [[ -z "$model" ]] && model="Unknown"
    [[ -z "$chip" ]] && chip="Unknown"
    [[ -z "$serial" ]] && serial="Unknown"

    add_audit_result --category 'Hardware, Firmware & Platform Integrity' \
        --control 'System Hardware Identification' --status INFO --severity Informational \
        --current "Model=$model; Chip/CPU=$chip; Serial=$serial" --recommended 'N/A' \
        --cis-macos 'CIS-macOS 1.1' --mscp 'N/A' \
        --recommendation 'Informational only. Confirm this asset record matches your inventory/MDM record.'
}

check_boot_rom_firmware_version() {
    run_root system_profiler SPiBridgeDataType
    local fw
    fw=$(print -r -- "$ROOT_CMD_OUTPUT" | awk -F': ' '/Firmware Version|Boot ROM Version|iBridge/{print $2; exit}')
    [[ -z "$fw" ]] && fw="Unknown"

    add_audit_result --category 'Hardware, Firmware & Platform Integrity' \
        --control 'Boot ROM / System Firmware Version' --status INFO --severity Informational \
        --current "$fw" --recommended 'Latest firmware per macOS Software Update' \
        --cis-macos 'CIS-macOS 1.1' --mscp 'N/A' \
        --recommendation 'Informational only. Firmware updates ship bundled with macOS Software Update; keep the OS current.'
}

# ---- 11-sip-kernel.zsh ----
#
# Domain 2: SIP & Kernel Security

check_sip_status() {
    write_section_banner 'SIP & Kernel Security - System Integrity Protection'
    run_root csrutil status

    if [[ "$ROOT_CMD_OUTPUT" == *"disabled"* ]]; then
        add_audit_result --category 'SIP & Kernel Security' --control 'System Integrity Protection (SIP)' \
            --status FAIL --severity Critical --current "$ROOT_CMD_OUTPUT" \
            --recommended 'System Integrity Protection status: enabled.' \
            --cis 'CIS 10.5' --nist 'SI-7, SC-28' --mitre 'T1553.006' --iso27001 'A.8.24' --nis2 'Art.21(2)(d)' \
            --nsa 'NSA/CISA macOS Hardening Guidance' --cis-macos 'CIS-macOS 5.1.1' --mscp 'os_sip_enable' \
            --recommendation 'Re-enable SIP: boot into Recovery (Apple Silicon: hold the power button; Intel: Cmd+R) and run "csrutil enable" from Terminal, then reboot.'
    elif [[ "$ROOT_CMD_OUTPUT" == *"enabled"* ]]; then
        add_audit_result --category 'SIP & Kernel Security' --control 'System Integrity Protection (SIP)' \
            --status PASS --severity Critical --current "$ROOT_CMD_OUTPUT" \
            --recommended 'System Integrity Protection status: enabled.' \
            --cis 'CIS 10.5' --nist 'SI-7, SC-28' --mitre 'T1553.006' --iso27001 'A.8.24' --nis2 'Art.21(2)(d)' \
            --nsa 'NSA/CISA macOS Hardening Guidance' --cis-macos 'CIS-macOS 5.1.1' --mscp 'os_sip_enable' \
            --recommendation 'No action required.'
    else
        add_audit_result --category 'SIP & Kernel Security' --control 'System Integrity Protection (SIP)' \
            --status WARN --severity Low --current "Query failed or unrecognized output: $ROOT_CMD_OUTPUT" \
            --recommended 'System Integrity Protection status: enabled.' \
            --cis 'CIS 10.5' --nist 'SI-7, SC-28' --cis-macos 'CIS-macOS 5.1.1' --mscp 'os_sip_enable' \
            --recommendation 'Unable to determine SIP status via csrutil; verify manually with "csrutil status" in Terminal.'
    fi
}

check_sip_custom_configuration() {
    run_root csrutil status

    if [[ "$ROOT_CMD_STATUS" -ne 0 ]]; then
        add_audit_result --category 'SIP & Kernel Security' --control 'SIP Custom Configuration (Partial Disable)' \
            --status WARN --severity Low --current "csrutil query failed: $ROOT_CMD_OUTPUT" \
            --recommended 'No custom SIP exceptions; full default protection set' \
            --cis-macos 'CIS-macOS 5.1.1' --mscp 'os_sip_enable' \
            --recommendation 'Unable to query SIP configuration; verify manually with "csrutil status" in Terminal.'
    elif [[ "$ROOT_CMD_OUTPUT" == *"Custom Configuration"* ]]; then
        local disabled_items
        disabled_items=$(print -r -- "$ROOT_CMD_OUTPUT" | grep ': disabled' | sed 's/^[[:space:]]*//' | paste -sd '; ' -)
        [[ -z "$disabled_items" ]] && disabled_items="Custom configuration detected but no specific disabled component parsed"
        add_audit_result --category 'SIP & Kernel Security' --control 'SIP Custom Configuration (Partial Disable)' \
            --status WARN --severity High --current "$disabled_items" \
            --recommended 'No custom SIP exceptions; full default protection set' \
            --cis 'CIS 10.5' --nist 'SI-7, SC-28' --mitre 'T1553.006' --iso27001 'A.8.24' --nis2 'Art.21(2)(d)' \
            --cis-macos 'CIS-macOS 5.1.1' --mscp 'os_sip_enable' \
            --recommendation 'A custom SIP configuration was detected, weakening specific protections. Boot into Recovery and run "csrutil clear" then "csrutil enable" to restore the full default protection set unless this is a deliberate, documented exception.'
    else
        add_audit_result --category 'SIP & Kernel Security' --control 'SIP Custom Configuration (Partial Disable)' \
            --status PASS --severity High --current 'No custom SIP configuration detected' \
            --recommended 'No custom SIP exceptions; full default protection set' \
            --cis 'CIS 10.5' --nist 'SI-7, SC-28' --cis-macos 'CIS-macOS 5.1.1' --mscp 'os_sip_enable' \
            --recommendation 'No action required.'
    fi
}

check_third_party_system_extensions() {
    run_root systemextensionsctl list

    if [[ "$ROOT_CMD_STATUS" -ne 0 ]]; then
        add_audit_result --category 'SIP & Kernel Security' --control 'Third-Party System Extensions Inventory' \
            --status WARN --severity Low --current "systemextensionsctl query failed: $ROOT_CMD_OUTPUT" \
            --recommended 'Every active system extension is recognized and required' \
            --cis-macos 'CIS-macOS 5.1' --mscp 'os_kext_signing_enforce' \
            --recommendation 'Unable to query system extensions; verify manually with "systemextensionsctl list" in Terminal.'
        return
    fi

    local activated_lines
    activated_lines=$(print -r -- "$ROOT_CMD_OUTPUT" | grep -c 'activated enabled')

    local -a nonapple_lines nonapple_ids=()
    nonapple_lines=("${(@f)$(print -r -- "$ROOT_CMD_OUTPUT" | grep 'activated enabled' | grep -v 'com\.apple\.')}")
    local nl
    for nl in "${nonapple_lines[@]}"; do
        [[ -z "$nl" ]] && continue
        local -a words
        words=(${=nl})
        nonapple_ids+=("${words[4]}")
    done
    local nonapple_count=${#nonapple_ids[@]}
    local joined
    joined=$(printf '%s\n' "${nonapple_ids[@]}")

    if [[ "$nonapple_count" -gt 0 ]]; then
        add_audit_result --category 'SIP & Kernel Security' --control 'Third-Party System Extensions Inventory' \
            --status WARN --severity Medium \
            --current "$nonapple_count non-Apple system extension(s) active (of $activated_lines total)" \
            --details "$joined" \
            --recommended 'Every active system extension is recognized and required' \
            --cis 'CIS 2.5' --nist 'CM-7, SI-7' --mitre 'T1547 (Boot or Logon Autostart Execution)' --iso27001 'A.8.19' \
            --cis-macos 'CIS-macOS 5.1' --mscp 'os_kext_signing_enforce' \
            --recommendation 'Review "systemextensionsctl list" output and confirm each non-Apple system extension is recognized, still needed, and from a trusted vendor.'
    else
        add_audit_result --category 'SIP & Kernel Security' --control 'Third-Party System Extensions Inventory' \
            --status PASS --severity Medium \
            --current "$activated_lines total active system extension(s), none non-Apple" \
            --recommended 'Every active system extension is recognized and required' \
            --cis 'CIS 2.5' --nist 'CM-7, SI-7' --cis-macos 'CIS-macOS 5.1' --mscp 'os_kext_signing_enforce' \
            --recommendation 'No action required.'
    fi
}

check_nvram_csr_override() {
    run_root nvram csr-active-config

    if [[ "$ROOT_CMD_STATUS" -eq 0 && -n "$ROOT_CMD_OUTPUT" ]]; then
        add_audit_result --category 'SIP & Kernel Security' --control 'NVRAM SIP Configuration Override Present' \
            --status WARN --severity Medium --current "$ROOT_CMD_OUTPUT" \
            --recommended 'No csr-active-config NVRAM variable set (default SIP configuration)' \
            --cis 'CIS 10.5' --nist 'SI-7, SC-28' --cis-macos 'CIS-macOS 5.1.1' --mscp 'os_sip_enable' \
            --recommendation 'An explicit SIP configuration override is stored in NVRAM. Confirm this was set deliberately; clear it with "nvram -d csr-active-config" from Recovery if not.'
    elif [[ "$ROOT_CMD_OUTPUT" == *"Error getting variable"* ]]; then
        add_audit_result --category 'SIP & Kernel Security' --control 'NVRAM SIP Configuration Override Present' \
            --status PASS --severity Medium --current 'No csr-active-config NVRAM variable set' \
            --recommended 'No csr-active-config NVRAM variable set (default SIP configuration)' \
            --cis 'CIS 10.5' --nist 'SI-7, SC-28' --cis-macos 'CIS-macOS 5.1.1' --mscp 'os_sip_enable' \
            --recommendation 'No action required.'
    else
        add_audit_result --category 'SIP & Kernel Security' --control 'NVRAM SIP Configuration Override Present' \
            --status WARN --severity Low --current "nvram query failed: $ROOT_CMD_OUTPUT" \
            --recommended 'No csr-active-config NVRAM variable set (default SIP configuration)' \
            --cis-macos 'CIS-macOS 5.1.1' --mscp 'os_sip_enable' \
            --recommendation 'Unable to query NVRAM SIP override state; verify manually with "nvram csr-active-config" in Terminal.'
    fi
}

# ---- 12-filevault.zsh ----
#
# Domain 3: Volume Encryption & Data-at-Rest (FileVault)

check_filevault_status() {
    write_section_banner 'Volume Encryption & Data-at-Rest (FileVault) - FileVault Status'
    run_root fdesetup status

    if [[ "$ROOT_CMD_OUTPUT" == *"FileVault is On."* ]]; then
        add_audit_result --category 'Volume Encryption & Data-at-Rest (FileVault)' --control 'FileVault Status' \
            --status PASS --severity Critical --current "$ROOT_CMD_OUTPUT" --recommended 'FileVault is On.' \
            --cis 'CIS 3.11' --nist 'SC-28' --mitre 'T1486 (Data Encrypted for Impact — inverse control)' \
            --iso27001 'A.8.24' --nis2 'Art.21(2)(h)' --nsa 'NSA/CISA Data-at-Rest Encryption Guidance' \
            --cis-macos 'CIS-macOS 3.1' --mscp 'os_filevault_enable' \
            --recommendation 'No action required.'
    elif [[ "$ROOT_CMD_OUTPUT" == *"FileVault is Off."* ]]; then
        add_audit_result --category 'Volume Encryption & Data-at-Rest (FileVault)' --control 'FileVault Status' \
            --status FAIL --severity Critical --current "$ROOT_CMD_OUTPUT" --recommended 'FileVault is On.' \
            --cis 'CIS 3.11' --nist 'SC-28' --mitre 'T1486 (Data Encrypted for Impact — inverse control)' \
            --iso27001 'A.8.24' --nis2 'Art.21(2)(h)' --nsa 'NSA/CISA Data-at-Rest Encryption Guidance' \
            --cis-macos 'CIS-macOS 3.1' --mscp 'os_filevault_enable' \
            --recommendation 'Enable FileVault via System Settings > Privacy & Security > FileVault, or run "sudo fdesetup enable" from Terminal.'
    else
        add_audit_result --category 'Volume Encryption & Data-at-Rest (FileVault)' --control 'FileVault Status' \
            --status WARN --severity Low --current "Query failed or unrecognized output: $ROOT_CMD_OUTPUT" \
            --recommended 'FileVault is On.' \
            --cis 'CIS 3.11' --nist 'SC-28' --cis-macos 'CIS-macOS 3.1' --mscp 'os_filevault_enable' \
            --recommendation 'Unable to determine FileVault status via fdesetup; verify manually with "fdesetup status" in Terminal.'
    fi
}

check_filevault_deferred_enablement() {
    run_root fdesetup status

    if [[ "$ROOT_CMD_OUTPUT" == *"Deferred enablement"* ]]; then
        add_audit_result --category 'Volume Encryption & Data-at-Rest (FileVault)' \
            --control 'FileVault Deferred Enablement Pending' \
            --status WARN --severity Medium --current "$ROOT_CMD_OUTPUT" \
            --recommended 'No deferred enablement pending' \
            --cis 'CIS 3.11' --nist 'SC-28' --mitre 'T1486 (Data Encrypted for Impact — inverse control)' \
            --iso27001 'A.8.24' --nis2 'Art.21(2)(h)' --nsa 'NSA/CISA Data-at-Rest Encryption Guidance' \
            --cis-macos 'CIS-macOS 3.1' --mscp 'os_filevault_enable, os_filevault_autologin_disable' \
            --recommendation 'Have the affected user log out and back in to complete FileVault encryption; deferred enablement leaves the volume unencrypted until then.'
    elif [[ "$ROOT_CMD_STATUS" -eq 0 ]]; then
        # Absence-of-bad-signal branch: only reachable once we know the
        # fdesetup query itself actually succeeded, per the Global
        # Constraints fault-isolation rule — a failing/missing command must
        # not fall through here and be reported identically to a verified
        # "no deferred enablement pending" result.
        add_audit_result --category 'Volume Encryption & Data-at-Rest (FileVault)' \
            --control 'FileVault Deferred Enablement Pending' \
            --status PASS --severity Medium --current 'No deferred enablement pending' \
            --recommended 'No deferred enablement pending' \
            --cis 'CIS 3.11' --nist 'SC-28' --mitre 'T1486 (Data Encrypted for Impact — inverse control)' \
            --iso27001 'A.8.24' --nis2 'Art.21(2)(h)' --nsa 'NSA/CISA Data-at-Rest Encryption Guidance' \
            --cis-macos 'CIS-macOS 3.1' --mscp 'os_filevault_enable, os_filevault_autologin_disable' \
            --recommendation 'No action required.'
    else
        add_audit_result --category 'Volume Encryption & Data-at-Rest (FileVault)' \
            --control 'FileVault Deferred Enablement Pending' \
            --status WARN --severity Low --current "fdesetup query failed: $ROOT_CMD_OUTPUT" \
            --recommended 'No deferred enablement pending' \
            --cis-macos 'CIS-macOS 3.1' --mscp 'os_filevault_enable, os_filevault_autologin_disable' \
            --recommendation 'Unable to determine FileVault deferred enablement state; verify manually with "fdesetup status" in Terminal.'
    fi
}

check_filevault_enabled_user_count() {
    run_root fdesetup list

    if [[ "$ROOT_CMD_STATUS" -ne 0 ]]; then
        # Fault isolation: a failed/missing "fdesetup list" query must not
        # be reported as "0 user(s) authorized" — that would be
        # indistinguishable from a genuine (and separately concerning)
        # zero-authorized-users result.
        add_audit_result --category 'Volume Encryption & Data-at-Rest (FileVault)' \
            --control 'FileVault-Authorized User Count' \
            --status WARN --severity Low --current "fdesetup list query failed: $ROOT_CMD_OUTPUT" \
            --recommended 'N/A' --cis-macos 'CIS-macOS 3.1' --mscp 'N/A' \
            --recommendation 'Unable to query FileVault-authorized users; verify manually with "sudo fdesetup list" in Terminal.'
        return
    fi

    local -a raw_users users=()
    raw_users=("${(@f)$(print -r -- "$ROOT_CMD_OUTPUT" | grep -ve '^[[:space:]]*$')}")
    local u
    for u in "${raw_users[@]}"; do
        # Zero grep matches still yields a one-element array holding an
        # empty string, not zero elements — without this guard, a
        # genuinely empty authorized-user list would count as "1
        # user(s)" instead of 0.
        [[ -n "$u" ]] && users+=("$u")
    done
    local joined
    joined=$(printf '%s\n' "${users[@]}")

    add_audit_result --category 'Volume Encryption & Data-at-Rest (FileVault)' \
        --control 'FileVault-Authorized User Count' \
        --status INFO --severity Informational \
        --current "${#users[@]} user(s) authorized to unlock FileVault" --details "$joined" --recommended 'N/A' \
        --cis-macos 'CIS-macOS 3.1' --mscp 'N/A' \
        --recommendation 'Informational only. Confirm this list matches expected FileVault-authorized users.'
}

check_filevault_recovery_key_escrow() {
    run_root test -e /var/db/FileVaultPRK.dat

    # Always INFO, per honesty-over-false-precision (same style as
    # Task 24's Time Machine encryption note): the presence of this file
    # means a personal recovery key exists locally, pending escrow; its
    # absence is genuinely ambiguous — already escrowed, an institutional
    # key was used instead, or FileVault uses a different unlock method
    # entirely — verified live that "fdesetup status -extended" carries
    # no escrow-status field at all, so there is no reliable CLI signal
    # either way.
    if [[ $ROOT_CMD_STATUS -eq 0 ]]; then
        add_audit_result --category 'Volume Encryption & Data-at-Rest (FileVault)' \
            --control 'FileVault Recovery Key Escrow' \
            --status INFO --severity Informational \
            --current 'A personal recovery key (FileVaultPRK.dat) is present locally, pending escrow' \
            --recommended 'N/A' --cis-macos 'CIS-macOS 3.1' --mscp 'N/A' \
            --recommendation 'Confirm this recovery key completes escrow to your MDM/institutional record; do not rely on it remaining only on this device.'
    else
        add_audit_result --category 'Volume Encryption & Data-at-Rest (FileVault)' \
            --control 'FileVault Recovery Key Escrow' \
            --status INFO --severity Informational \
            --current 'No pending local personal recovery key file found; escrow status cannot be reliably determined from the command line' \
            --recommended 'N/A' --cis-macos 'CIS-macOS 3.1' --mscp 'N/A' \
            --recommendation 'Informational only. Confirm recovery-key escrow status manually via your MDM console.'
    fi
}

# ---- 13-gatekeeper.zsh ----
#
# Domain 4: Gatekeeper, Notarization & Application Control

check_gatekeeper_status() {
    write_section_banner 'Gatekeeper, Notarization & Application Control - Gatekeeper Status'
    run_root spctl --status

    if [[ "$ROOT_CMD_OUTPUT" == *"assessments enabled"* ]]; then
        add_audit_result --category 'Gatekeeper, Notarization & Application Control' \
            --control 'Gatekeeper Status' \
            --status PASS --severity High --current "$ROOT_CMD_OUTPUT" \
            --recommended 'assessments enabled' \
            --cis 'CIS 2.5' --nist 'CM-7, SI-7' --mitre 'T1553.001 (Gatekeeper Bypass)' --iso27001 'A.8.19' \
            --nis2 'Art.21(2)(d)' --nsa 'NSA/CISA macOS Hardening Guidance' \
            --cis-macos 'CIS-macOS 5.1.4' --mscp 'os_gatekeeper_enable' \
            --recommendation 'No action required.'
    elif [[ "$ROOT_CMD_OUTPUT" == *"assessments disabled"* ]]; then
        add_audit_result --category 'Gatekeeper, Notarization & Application Control' \
            --control 'Gatekeeper Status' \
            --status FAIL --severity High --current "$ROOT_CMD_OUTPUT" \
            --recommended 'assessments enabled' \
            --cis 'CIS 2.5' --nist 'CM-7, SI-7' --mitre 'T1553.001 (Gatekeeper Bypass)' --iso27001 'A.8.19' \
            --nis2 'Art.21(2)(d)' --nsa 'NSA/CISA macOS Hardening Guidance' \
            --cis-macos 'CIS-macOS 5.1.4' --mscp 'os_gatekeeper_enable' \
            --recommendation 'Re-enable Gatekeeper: run "sudo spctl --master-enable" in Terminal, or enable it via System Settings > Privacy & Security > Security ("App Store and identified developers").'
    else
        # Fault isolation: PASS above is only reached on an explicit
        # "assessments enabled" match, never on the mere absence of
        # "assessments disabled" — so a failing/missing spctl query falls
        # through to this WARN branch instead of being silently reported as
        # a verified-clean Gatekeeper status.
        add_audit_result --category 'Gatekeeper, Notarization & Application Control' \
            --control 'Gatekeeper Status' \
            --status WARN --severity Low --current "Query failed or unrecognized output: $ROOT_CMD_OUTPUT" \
            --recommended 'assessments enabled' \
            --cis 'CIS 2.5' --nist 'CM-7, SI-7' --cis-macos 'CIS-macOS 5.1.4' --mscp 'os_gatekeeper_enable' \
            --recommendation 'Unable to determine Gatekeeper status via spctl; verify manually with "spctl --status" in Terminal.'
    fi
}

_quarantine_event_count() {
    local db_path="$1"
    sqlite_value_safe "$db_path" "SELECT COUNT(*) FROM LSQuarantineEvent;" "0"
}

check_quarantine_enforcement_telemetry() {
    if [[ -z "$CONSOLE_USER" ]]; then
        add_audit_result --category 'Gatekeeper, Notarization & Application Control' \
            --control 'Quarantine Enforcement Telemetry' \
            --status WARN --severity Low --current 'No console user detected' \
            --recommended 'N/A' \
            --cis-macos 'CIS-macOS 5.1.4' --mscp 'N/A' \
            --recommendation 'Re-run interactively at a console login session to evaluate quarantine event telemetry.'
        return
    fi

    local db_path
    db_path="$(eval echo ~$CONSOLE_USER)/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"
    local count
    count=$(_quarantine_event_count "$db_path")

    # Always INFO: honesty over false precision — a low or zero quarantine
    # event count on a freshly-imaged Mac is not itself a finding, it is
    # simply telemetry to review.
    add_audit_result --category 'Gatekeeper, Notarization & Application Control' \
        --control 'Quarantine Enforcement Telemetry' \
        --status INFO --severity Informational \
        --current "$count quarantine event(s) recorded" --recommended 'N/A' \
        --cis-macos 'CIS-macOS 5.1.4' --mscp 'N/A' \
        --recommendation 'Informational only. Gatekeeper/quarantine records one event each time it evaluates a downloaded file; a nonzero count confirms the quarantine mechanism is actively logging.'
}

_gatekeeper_scan_apps_dir() {
    local dir="$1"
    run_root find "$dir" -maxdepth 1 -name '*.app'

    local -a apps
    apps=("${(@f)ROOT_CMD_OUTPUT}")

    local total=0 flagged=0 app
    local -a flagged_names=()
    for app in "${apps[@]}"; do
        [[ -z "$app" ]] && continue
        total=$((total + 1))
        run_root xattr -p com.apple.quarantine "$app"
        # Real xattr behavior (verified live): exit 0 with the attribute
        # value on stdout when the quarantine flag is still present, exit
        # nonzero with an error on stderr when it is absent. Exit status,
        # not output text, is the signal.
        if [[ "$ROOT_CMD_STATUS" -eq 0 ]]; then
            flagged=$((flagged + 1))
            flagged_names+=("${app:t}")
        fi
    done
    local joined
    joined=$(printf '%s\n' "${flagged_names[@]}")

    # Always INFO: this is inventory, not a judgement — an app can
    # legitimately lose its quarantine flag after first launch.
    add_audit_result --category 'Gatekeeper, Notarization & Application Control' \
        --control 'Installed Application Quarantine Flag Survey' \
        --status INFO --severity Informational \
        --current "$flagged/$total installed application(s) still carry the quarantine attribute" \
        --details "$joined" \
        --recommended 'N/A' \
        --cis-macos 'CIS-macOS 5.1.4' --mscp 'N/A' \
        --recommendation 'Informational only. Quarantine flags are commonly cleared on first launch; use this as an inventory baseline, not a pass/fail signal.'
}

check_applications_quarantine_flag_survey() {
    _gatekeeper_scan_apps_dir '/Applications'
}

# ---- 14-malware-defense.zsh ----
#
# Domain 5: Malware Defense (XProtect / MRT / EDR)

# Shared freshness check for a system-supplied malware-defense bundle
# (XProtect.bundle, MRT.app). Independently testable against a scratch
# plist: pass a real path/key pair and a control-name to drive it.
#
# control_name doubles as the source of the short "bundle label" used in
# the missing-file message (its first word, e.g. "XProtect" / "MRT") and
# is used to select the correct mSCP control id, since both callers share
# every other mapping value.
_bundle_freshness_check() {
    local plist_path="$1" version_key="$2" control_name="$3"
    local bundle_label="${control_name%% *}"

    local mscp_id
    case "$control_name" in
        'XProtect Update Freshness') mscp_id='os_xprotect_update' ;;
        'MRT Update Freshness') mscp_id='os_mrt_update' ;;
        *) mscp_id='N/A' ;;
    esac

    if [[ ! -f "$plist_path" ]]; then
        # Fault isolation: a missing bundle gets its own distinct --current
        # text, never silently folded into the "stale" WARN below.
        add_audit_result --category 'Malware Defense (XProtect / MRT / EDR)' --control "$control_name" \
            --status WARN --severity Medium --current "${bundle_label} bundle not found at expected path" \
            --recommended 'Definitions updated within the last 30 days' \
            --cis 'CIS 7.2' --nist 'SI-3' --mitre 'T1204 (User Execution)' --iso27001 'A.8.7' \
            --nis2 'Art.21(2)(d)' --nsa 'NSA/CISA Malware Defense Guidance' --cis-macos 'CIS-macOS 1.3' \
            --mscp "$mscp_id" \
            --recommendation 'Run Software Update, or check "softwareupdate --background-critical", to fetch the latest malware definitions.'
        return
    fi

    local version
    version=$(plist_value_safe "$plist_path" "$version_key" "Unknown")
    version="${version%.000000}"

    local mtime now age_days
    mtime=$(stat -f %m "$plist_path")
    now=$(date +%s)
    age_days=$(( (now - mtime) / 86400 ))

    if (( age_days <= 30 )); then
        add_audit_result --category 'Malware Defense (XProtect / MRT / EDR)' --control "$control_name" \
            --status PASS --severity Medium --current "Version=$version, last updated $age_days day(s) ago" \
            --recommended 'Definitions updated within the last 30 days' \
            --cis 'CIS 7.2' --nist 'SI-3' --mitre 'T1204 (User Execution)' --iso27001 'A.8.7' \
            --nis2 'Art.21(2)(d)' --nsa 'NSA/CISA Malware Defense Guidance' --cis-macos 'CIS-macOS 1.3' \
            --mscp "$mscp_id" \
            --recommendation 'No action required.'
    else
        add_audit_result --category 'Malware Defense (XProtect / MRT / EDR)' --control "$control_name" \
            --status WARN --severity Medium --current "Version=$version, last updated $age_days day(s) ago" \
            --recommended 'Definitions updated within the last 30 days' \
            --cis 'CIS 7.2' --nist 'SI-3' --mitre 'T1204 (User Execution)' --iso27001 'A.8.7' \
            --nis2 'Art.21(2)(d)' --nsa 'NSA/CISA Malware Defense Guidance' --cis-macos 'CIS-macOS 1.3' \
            --mscp "$mscp_id" \
            --recommendation 'Run Software Update, or check "softwareupdate --background-critical", to fetch the latest malware definitions.'
    fi
}

check_xprotect_freshness() {
    write_section_banner 'Malware Defense (XProtect / MRT / EDR) - XProtect Freshness'
    _bundle_freshness_check \
        '/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.meta.plist' \
        'Version' 'XProtect Update Freshness'
}

check_mrt_freshness() {
    _bundle_freshness_check \
        '/Library/Apple/System/Library/CoreServices/MRT.app/Contents/Info.plist' \
        'CFBundleShortVersionString' 'MRT Update Freshness'
}

check_third_party_edr_presence() {
    run_root launchctl list

    if [[ "$ROOT_CMD_STATUS" -ne 0 ]]; then
        # Fault isolation: a failing launchctl query must never be reported
        # identically to a verified "no EDR agent found" result below.
        add_audit_result --category 'Malware Defense (XProtect / MRT / EDR)' --control 'Third-Party EDR/MDE Presence' \
            --status WARN --severity Low --current "launchctl query failed: $ROOT_CMD_OUTPUT" \
            --recommended 'N/A' --cis-macos 'CIS-macOS 1.3' --mscp 'N/A' \
            --recommendation 'Unable to enumerate running processes; verify manually with "launchctl list" in Terminal.'
        return
    fi

    local -a edr_labels
    edr_labels=(com.crowdstrike com.sentinelone com.microsoft.wdav com.carbonblack com.paloaltonetworks com.cisco.amp)
    local -a matched=()
    local label

    for label in "${edr_labels[@]}"; do
        if [[ "$ROOT_CMD_OUTPUT" == *"$label"* ]]; then
            matched+=("$label")
        fi
    done

    if (( ${#matched[@]} > 0 )); then
        local joined
        joined=$(printf '%s, ' "${matched[@]}")
        joined="${joined%, }"
        add_audit_result --category 'Malware Defense (XProtect / MRT / EDR)' --control 'Third-Party EDR/MDE Presence' \
            --status INFO --severity Informational --current "EDR agent(s) detected: $joined" \
            --recommended 'N/A' \
            --cis 'CIS 7.1' --nist 'SI-3' --mitre 'T1562.001 (Disable or Modify Tools)' --iso27001 'A.8.7' \
            --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 1.3' --mscp 'N/A' \
            --recommendation 'Informational only. A recognized third-party EDR/MDE agent process is running.'
    else
        add_audit_result --category 'Malware Defense (XProtect / MRT / EDR)' --control 'Third-Party EDR/MDE Presence' \
            --status WARN --severity Medium --current 'No known third-party EDR/MDE agent process detected' \
            --recommended 'A recognized EDR/MDE agent process is running' \
            --cis 'CIS 7.1' --nist 'SI-3' --mitre 'T1562.001 (Disable or Modify Tools)' --iso27001 'A.8.7' \
            --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 1.3' --mscp 'N/A' \
            --recommendation 'Confirm whether an EDR agent is expected on this fleet tier; XProtect/MRT alone provide baseline malware defense coverage only.'
    fi
}

check_endpoint_security_clients() {
    run_root systemextensionsctl list

    # Parse only the "com.apple.system_extension.endpoint_security"
    # section — a much stronger EDR-presence signal than grepping
    # `launchctl list` for vendor labels, since it reflects Apple's own
    # Endpoint Security framework registration rather than a guessable
    # process name. Verified live: with none installed, the whole
    # command's output is just "0 extension(s)" with no "---" section at
    # all, so an absent section is the normal/expected case, not a
    # parse failure.
    local -a lines
    lines=("${(@f)ROOT_CMD_OUTPUT}")
    local in_section=0 count=0 line
    for line in "${lines[@]}"; do
        if [[ "$line" == '--- com.apple.system_extension.endpoint_security'* ]]; then
            in_section=1
            continue
        fi
        if [[ "$line" == '---'* ]]; then
            in_section=0
            continue
        fi
        (( ! in_section )) && continue
        [[ "$line" == enabled*active* ]] && continue
        [[ -z "${line//[[:space:]]/}" ]] && continue
        count=$((count + 1))
    done

    # Always INFO: this is inventory that complements, not replaces, the
    # judgement-bearing "Third-Party EDR/MDE Presence" check above — kept
    # separate per the "no duplicate/contradictory checks" principle.
    add_audit_result --category 'Malware Defense (XProtect / MRT / EDR)' --control 'Endpoint Security Framework Clients' \
        --status INFO --severity Informational --current "$count Endpoint Security framework client(s) registered" \
        --recommended 'N/A' --cis-macos 'CIS-macOS 1.3' --mscp 'N/A' \
        --recommendation 'Informational only. This reflects Endpoint Security framework registration specifically, which is a stronger EDR-presence signal than a running-process check.'
}

# ---- 15-tcc-privacy.zsh ----
#
# Domain 6: TCC & Privacy Controls

# Lists the client bundle IDs granted for a given TCC service. macOS's
# own TCC protection blocks sqlite3 from opening TCC.db — even as root —
# unless the calling process has itself been granted Full Disk Access, so
# a plain sqlite_value_safe (which folds every failure into its default)
# cannot be used here: it would report "0 app(s) granted" identically for
# a genuinely clean system and a query that never ran at all. Instead
# this prints one of three distinguishable markers so every caller can
# tell the three cases apart:
#   - a (possibly empty) newline-separated client list: the real,
#     successful result
#   - "AUTH_DENIED": the query was blocked by TCC's own protection
#   - "QUERY_ERROR:<output>": some other command failure
#
# db_path defaults to the real system database but takes an override so
# this is directly testable against a scratch db, same as Task 9's
# _quarantine_event_count fixture.
_tcc_grant_clients() {
    local service="$1"
    local db="${2:-/Library/Application Support/com.apple.TCC/TCC.db}"
    run_root sqlite3 "$db" "SELECT client FROM access WHERE service='$service' AND auth_value=2;"

    if [[ "$ROOT_CMD_OUTPUT" == *"authorization denied"* ]]; then
        printf 'AUTH_DENIED'
        return 1
    fi

    if [[ $ROOT_CMD_STATUS -eq 0 ]]; then
        printf '%s' "$ROOT_CMD_OUTPUT"
        return 0
    fi

    printf 'QUERY_ERROR:%s' "$ROOT_CMD_OUTPUT"
    return 2
}

# Shared reporting for the three single-service grant checks. `label` is
# the human-readable service name used in the --current text; `control`
# is the full control name used in --control. The granted client list —
# derived from the same query, not a separate COUNT(*) call — becomes the
# hover-tooltip --details, so a security reviewer can see exactly which
# apps hold Full Disk Access without a second, redundant finding row.
_tcc_report_service_grant() {
    local control="$1" label="$2" service="$3"
    local result
    result=$(_tcc_grant_clients "$service")

    case "$result" in
        AUTH_DENIED)
            add_audit_result --category 'TCC & Privacy Controls' --control "$control" \
                --status WARN --severity Low \
                --current 'Unable to query TCC database — authorization denied' \
                --recommended 'N/A' \
                --cis 'CIS 3.3' --nist 'AC-6' --mitre 'T1005 (Data from Local System)' --iso27001 'A.8.3' \
                --nis2 'Art.21(2)(i)' --cis-macos 'CIS-macOS 5.1.3' --mscp 'N/A' \
                --recommendation 'Grant Full Disk Access to the terminal application (or shell) used to run this script in System Settings > Privacy & Security > Full Disk Access, then re-run.'
            ;;
        QUERY_ERROR:*)
            add_audit_result --category 'TCC & Privacy Controls' --control "$control" \
                --status WARN --severity Low \
                --current "TCC database query failed: ${result#QUERY_ERROR:}" \
                --recommended 'N/A' \
                --cis 'CIS 3.3' --nist 'AC-6' --mitre 'T1005 (Data from Local System)' --iso27001 'A.8.3' \
                --nis2 'Art.21(2)(i)' --cis-macos 'CIS-macOS 5.1.3' --mscp 'N/A' \
                --recommendation 'Unable to determine grant count; verify manually by querying the TCC database as an administrator with Full Disk Access.'
            ;;
        *)
            local -a clients nonempty=()
            clients=("${(@f)result}")
            local c
            for c in "${clients[@]}"; do
                [[ -n "$c" ]] && nonempty+=("$c")
            done
            local joined
            joined=$(printf '%s\n' "${nonempty[@]}")
            add_audit_result --category 'TCC & Privacy Controls' --control "$control" \
                --status INFO --severity Informational \
                --current "${#nonempty[@]} app(s) granted $label" --details "$joined" --recommended 'N/A' \
                --cis 'CIS 3.3' --nist 'AC-6' --mitre 'T1005 (Data from Local System)' --iso27001 'A.8.3' \
                --nis2 'Art.21(2)(i)' --cis-macos 'CIS-macOS 5.1.3' --mscp 'N/A' \
                --recommendation 'Informational only. Review the granted application list and confirm each grant is expected.'
            ;;
    esac
}

check_tcc_full_disk_access_grants() {
    write_section_banner 'TCC & Privacy Controls - Full Disk Access Grants'
    _tcc_report_service_grant 'Full Disk Access Grants' 'Full Disk Access' 'kTCCServiceSystemPolicyAllFiles'
}

check_tcc_screen_recording_grants() {
    _tcc_report_service_grant 'Screen Recording Grants' 'Screen Recording' 'kTCCServiceScreenCapture'
}

check_tcc_accessibility_grants() {
    _tcc_report_service_grant 'Accessibility Grants' 'Accessibility' 'kTCCServiceAccessibility'
}

check_tcc_camera_microphone_grants() {
    local camera mic

    camera=$(_tcc_grant_clients 'kTCCServiceCamera')
    case "$camera" in
        AUTH_DENIED|QUERY_ERROR:*)
            _tcc_report_camera_mic_failure "$camera"
            return
            ;;
    esac

    mic=$(_tcc_grant_clients 'kTCCServiceMicrophone')
    case "$mic" in
        AUTH_DENIED|QUERY_ERROR:*)
            _tcc_report_camera_mic_failure "$mic"
            return
            ;;
    esac

    local -a camera_clients=("${(@f)camera}") mic_clients=("${(@f)mic}")
    local -a camera_nonempty=() mic_nonempty=()
    local c
    for c in "${camera_clients[@]}"; do [[ -n "$c" ]] && camera_nonempty+=("$c"); done
    for c in "${mic_clients[@]}"; do [[ -n "$c" ]] && mic_nonempty+=("$c"); done

    local camera_joined mic_joined
    camera_joined=$(printf '%s\n' "${camera_nonempty[@]}")
    mic_joined=$(printf '%s\n' "${mic_nonempty[@]}")
    local details_text="Camera:"$'\n'"${camera_joined:-(none)}"$'\n\n'"Microphone:"$'\n'"${mic_joined:-(none)}"

    add_audit_result --category 'TCC & Privacy Controls' --control 'Camera & Microphone Grants' \
        --status INFO --severity Informational \
        --current "Camera: ${#camera_nonempty[@]} app(s); Microphone: ${#mic_nonempty[@]} app(s)" \
        --details "$details_text" --recommended 'N/A' \
        --cis 'CIS 3.3' --nist 'AC-6' --mitre 'T1005 (Data from Local System)' --iso27001 'A.8.3' \
        --nis2 'Art.21(2)(i)' --cis-macos 'CIS-macOS 5.1.3' --mscp 'N/A' \
        --recommendation 'Informational only. Review the granted application list and confirm each grant is expected.'
}

# A denial/error on either half must fail the combined check closed —
# never report a partial count as if it were the real total.
_tcc_report_camera_mic_failure() {
    local result="$1"
    if [[ "$result" == "AUTH_DENIED" ]]; then
        add_audit_result --category 'TCC & Privacy Controls' --control 'Camera & Microphone Grants' \
            --status WARN --severity Low \
            --current 'Unable to query TCC database — authorization denied' \
            --recommended 'N/A' \
            --cis 'CIS 3.3' --nist 'AC-6' --mitre 'T1005 (Data from Local System)' --iso27001 'A.8.3' \
            --nis2 'Art.21(2)(i)' --cis-macos 'CIS-macOS 5.1.3' --mscp 'N/A' \
            --recommendation 'Grant Full Disk Access to the terminal application (or shell) used to run this script in System Settings > Privacy & Security > Full Disk Access, then re-run.'
    else
        add_audit_result --category 'TCC & Privacy Controls' --control 'Camera & Microphone Grants' \
            --status WARN --severity Low \
            --current "TCC database query failed: ${result#QUERY_ERROR:}" \
            --recommended 'N/A' \
            --cis 'CIS 3.3' --nist 'AC-6' --mitre 'T1005 (Data from Local System)' --iso27001 'A.8.3' \
            --nis2 'Art.21(2)(i)' --cis-macos 'CIS-macOS 5.1.3' --mscp 'N/A' \
            --recommendation 'Unable to determine grant count; verify manually by querying the TCC database as an administrator with Full Disk Access.'
    fi
}

check_tcc_database_permissions() {
    run_root stat -f '%Su:%Sg %Lp' '/Library/Application Support/com.apple.TCC/TCC.db'

    local owner_group="${ROOT_CMD_OUTPUT%% *}"
    local mode="${ROOT_CMD_OUTPUT##* }"

    # Fault isolation: only an explicit, well-formed "owner:group mode"
    # match below is judged PASS/FAIL; a failing stat or unparseable
    # output falls through here instead of being silently reported as a
    # verified-clean or verified-tampered result.
    if [[ $ROOT_CMD_STATUS -ne 0 || "$ROOT_CMD_OUTPUT" != *':'*' '* || ! "$mode" =~ '^[0-7]+$' ]]; then
        add_audit_result --category 'TCC & Privacy Controls' --control 'TCC Database File Permissions' \
            --status WARN --severity Low \
            --current "Query failed or unrecognized output: $ROOT_CMD_OUTPUT" \
            --recommended 'root:wheel (or root:_tcc), no group/other write bit' \
            --cis 'CIS 3.3' --nist 'AC-6, SI-7' --cis-macos 'CIS-macOS 5.1.3' --mscp 'N/A' \
            --recommendation 'Unable to verify TCC database file permissions; check manually with "stat -f \"%Su:%Sg %Lp\" \"/Library/Application Support/com.apple.TCC/TCC.db\"".'
        return
    fi

    local last3="${mode: -3}"
    local group_digit="${last3:1:1}" other_digit="${last3:2:1}"
    local tampered=0

    if [[ "$owner_group" != 'root:wheel' && "$owner_group" != 'root:_tcc' ]]; then
        tampered=1
    fi
    if (( (group_digit & 2) != 0 || (other_digit & 2) != 0 )); then
        tampered=1
    fi

    if (( tampered )); then
        add_audit_result --category 'TCC & Privacy Controls' --control 'TCC Database File Permissions' \
            --status FAIL --severity Critical \
            --current "$owner_group $mode" \
            --recommended 'root:wheel (or root:_tcc), no group/other write bit' \
            --cis 'CIS 3.3' --nist 'AC-6, SI-7' --mitre 'T1548.006 (TCC Manipulation)' --iso27001 'A.8.3' \
            --nis2 'Art.21(2)(d)' --nsa 'NSA/CISA macOS Hardening Guidance' --cis-macos 'CIS-macOS 5.1.3' --mscp 'N/A' \
            --recommendation 'This indicates SIP is compromised or the TCC database was tampered with outside Apple'"'"'s normal management path; treat as a possible active-compromise indicator and investigate before remediating.'
    else
        add_audit_result --category 'TCC & Privacy Controls' --control 'TCC Database File Permissions' \
            --status PASS --severity Critical \
            --current "$owner_group $mode" \
            --recommended 'root:wheel (or root:_tcc), no group/other write bit' \
            --cis 'CIS 3.3' --nist 'AC-6, SI-7' --mitre 'T1548.006 (TCC Manipulation)' --iso27001 'A.8.3' \
            --nis2 'Art.21(2)(d)' --nsa 'NSA/CISA macOS Hardening Guidance' --cis-macos 'CIS-macOS 5.1.3' --mscp 'N/A' \
            --recommendation 'No action required.'
    fi
}

# --- CIS Apple macOS 26 Tahoe v1.0.0 sections 2.6.1.1-2.6.1.2 (Level 2) ---

check_location_services_enabled() {
    run_root launchctl list
    local daemon_loaded=0
    [[ $ROOT_CMD_STATUS -eq 0 && "$ROOT_CMD_OUTPUT" == *"com.apple.locationd"* ]] && daemon_loaded=1
    # Read as the _locationd user, exactly as the CIS audit does: the
    # setting lives in that account's ByHost preferences.
    run_root sudo -u _locationd osascript -l JavaScript -e "var v = \$.NSUserDefaults.alloc.initWithSuiteName('com.apple.locationd').objectForKey('LocationServicesEnabled'); v.isNil() ? '' : String(ObjC.deepUnwrap(v))"
    local enabled="$ROOT_CMD_OUTPUT" enabled_status=$ROOT_CMD_STATUS
    local -a fw
    fw=(--recommended 'locationd loaded, LocationServicesEnabled=true' --cis 'CIS 4.1, 4.8' --nist 'CM-7'
        --iso27001 'A.8.9' --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 2.6.1.1' --mscp 'system_settings_location_services_enable')

    if [[ $enabled_status -ne 0 ]]; then
        add_audit_result --category 'TCC & Privacy Controls' --control 'Location Services Enabled' \
            --status WARN --severity Low --current "Query failed: $enabled" "${fw[@]}" \
            --recommendation 'Verify manually in System Settings > Privacy & Security > Location Services.'
    elif [[ $daemon_loaded -eq 1 && ( "$enabled" == "true" || "$enabled" == "1" ) ]]; then
        add_audit_result --category 'TCC & Privacy Controls' --control 'Location Services Enabled' \
            --status PASS --severity Low --current 'Location Services enabled' "${fw[@]}" --recommendation 'No action required.'
    else
        add_audit_result --category 'TCC & Privacy Controls' --control 'Location Services Enabled' \
            --status FAIL --severity Low --current "locationd loaded=$daemon_loaded, LocationServicesEnabled=${enabled:-not set}" "${fw[@]}" \
            --recommendation 'Enable Location Services (CIS Level 2: needed for accurate time zone and Find My) in System Settings > Privacy & Security > Location Services; restrict per-app access instead.'
    fi
}

check_location_services_menu_icon() {
    evaluate_managed_pref --category 'TCC & Privacy Controls' --control 'Location Icon Shown for System Services' \
        --severity Low --suite com.apple.locationmenu --key ShowSystemServices --expect 1 \
        --cis 'CIS 4.1, 4.8' --nist 'CM-7' --iso27001 'A.8.9' --nis2 'Art.21(2)(d)' \
        --cis-macos 'CIS-macOS 2.6.1.2' --mscp 'system_settings_location_services_menu_enforce' \
        --recommendation 'Enable "Show location icon in Control Center when System Services request your location" (Location Services > System Services > Details), or enforce ShowSystemServices=true via profile.'
}

# ---- 16-identity-accounts.zsh ----
#
# Domain 7: Identity, Accounts & Privilege Management

check_root_account_disabled() {
    write_section_banner 'Identity, Accounts & Privilege Management - Root Account Disabled'
    run_root dscl . -read /Users/root Password

    if [[ $ROOT_CMD_STATUS -ne 0 ]]; then
        # Fault isolation: a failing dscl query must never be reported
        # identically to either a verified-disabled or verified-enabled
        # root account below.
        add_audit_result --category 'Identity, Accounts & Privilege Management' \
            --control 'Root Account Disabled' \
            --status WARN --severity Low --current "dscl query failed: $ROOT_CMD_OUTPUT" \
            --recommended 'Password: *' \
            --cis 'CIS 5.4' --nist 'AC-6, IA-2' --cis-macos 'CIS-macOS 6.1' --mscp 'os_root_disable' \
            --recommendation 'Unable to determine root account status; verify manually with "dscl . -read /Users/root Password".'
    elif [[ "$ROOT_CMD_OUTPUT" == *"Password: *"* ]]; then
        add_audit_result --category 'Identity, Accounts & Privilege Management' \
            --control 'Root Account Disabled' \
            --status PASS --severity Critical --current "$ROOT_CMD_OUTPUT" \
            --recommended 'Password: *' \
            --cis 'CIS 5.4' --nist 'AC-6, IA-2' --mitre 'T1078.001 (Default Accounts)' --iso27001 'A.8.2' \
            --nis2 'Art.21(2)(i)' --nsa 'NSA/CISA macOS Hardening Guidance' --cis-macos 'CIS-macOS 6.1' --mscp 'os_root_disable' \
            --recommendation 'No action required.'
    else
        add_audit_result --category 'Identity, Accounts & Privilege Management' \
            --control 'Root Account Disabled' \
            --status FAIL --severity Critical --current "$ROOT_CMD_OUTPUT" \
            --recommended 'Password: *' \
            --cis 'CIS 5.4' --nist 'AC-6, IA-2' --mitre 'T1078.001 (Default Accounts)' --iso27001 'A.8.2' \
            --nis2 'Art.21(2)(i)' --nsa 'NSA/CISA macOS Hardening Guidance' --cis-macos 'CIS-macOS 6.1' --mscp 'os_root_disable' \
            --recommendation 'Disable the root account: use Directory Utility ("Disable Root User") or run "sudo dsenableroot -d" — resetting the root password with "dscl . -passwd" is not sufficient.'
    fi
}

check_guest_account_disabled() {
    local guest_enabled
    guest_enabled=$(defaults_read_safe '/Library/Preferences/com.apple.loginwindow' 'GuestEnabled' '0')

    if [[ "$guest_enabled" == "1" ]]; then
        add_audit_result --category 'Identity, Accounts & Privilege Management' \
            --control 'Guest Account Disabled' \
            --status FAIL --severity High --current 'GuestEnabled=1' \
            --recommended 'GuestEnabled=0' \
            --cis 'CIS 5.4' --nist 'AC-6, IA-2' --mitre 'T1078.001 (Default Accounts)' --iso27001 'A.8.2' \
            --nis2 'Art.21(2)(i)' --cis-macos 'CIS-macOS 6.2' --mscp 'os_guest_account_disable' \
            --recommendation 'Disable the Guest account: System Settings > Users & Groups > Guest User, or "sudo defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false".'
    else
        add_audit_result --category 'Identity, Accounts & Privilege Management' \
            --control 'Guest Account Disabled' \
            --status PASS --severity High --current "GuestEnabled=$guest_enabled" \
            --recommended 'GuestEnabled=0' \
            --cis 'CIS 5.4' --nist 'AC-6, IA-2' --mitre 'T1078.001 (Default Accounts)' --iso27001 'A.8.2' \
            --nis2 'Art.21(2)(i)' --cis-macos 'CIS-macOS 6.2' --mscp 'os_guest_account_disable' \
            --recommendation 'No action required.'
    fi
}

check_admin_group_membership_inventory() {
    run_root dscl . -read /Groups/admin GroupMembership

    if [[ $ROOT_CMD_STATUS -ne 0 ]]; then
        # Fault isolation: a failing dscl query must never be reported as
        # a legitimate (and misleadingly reassuring) empty admin roster.
        add_audit_result --category 'Identity, Accounts & Privilege Management' \
            --control 'Admin Group Membership Inventory' \
            --status WARN --severity Low --current "dscl query failed: $ROOT_CMD_OUTPUT" \
            --recommended 'N/A' --cis-macos 'CIS-macOS 6.3' --mscp 'N/A' \
            --recommendation 'Unable to enumerate admin group membership; verify manually with "dscl . -read /Groups/admin GroupMembership".'
        return
    fi

    local raw members joined count
    raw="${ROOT_CMD_OUTPUT#GroupMembership:}"
    members=(${=raw})
    count=${#members[@]}
    joined=$(printf '%s\n' "${members[@]}")

    # Always INFO: membership size alone isn't a judgement — matches the
    # "defaults aren't automatically findings" principle.
    add_audit_result --category 'Identity, Accounts & Privilege Management' \
        --control 'Admin Group Membership Inventory' \
        --status INFO --severity Informational \
        --current "$count member(s)" --details "$joined" --recommended 'N/A' \
        --cis 'CIS 5.1' --nist 'AC-6' --iso27001 'A.8.2' --cis-macos 'CIS-macOS 6.3' --mscp 'N/A' \
        --recommendation 'Informational only. Confirm the admin roster matches the expected list of privileged users.'
}

check_password_policy_configured() {
    run_root pwpolicy getaccountpolicies

    if [[ $ROOT_CMD_STATUS -eq 0 && "$ROOT_CMD_OUTPUT" == *"policyAttribute"* ]]; then
        # Real "pwpolicy getaccountpolicies" output (verified live) is a
        # full XML plist — dumping its first 200 raw characters into the
        # report showed literal "<?xml version..." markup to the reader.
        # Extract just the human-readable rule text from each
        # "<string>policyAttribute...</string>" line instead.
        local -a lines rules=()
        lines=("${(@f)ROOT_CMD_OUTPUT}")
        local line
        for line in "${lines[@]}"; do
            if [[ "$line" =~ '<string>(policyAttribute[^<]*)</string>' ]]; then
                rules+=("${match[1]}")
            fi
        done
        local -a unique_rules
        unique_rules=("${(@u)rules}")
        local joined
        joined=$(printf '%s\n' "${unique_rules[@]}")

        add_audit_result --category 'Identity, Accounts & Privilege Management' \
            --control 'Password Policy Configured' \
            --status INFO --severity Informational \
            --current "${#unique_rules[@]} password content rule(s) configured" --details "$joined" --recommended 'N/A' \
            --cis 'CIS 5.2' --nist 'IA-5' --mitre 'T1110 (Brute Force)' --iso27001 'A.8.5' \
            --nis2 'Art.21(2)(i)' --cis-macos 'CIS-macOS 6.4' --mscp 'os_policy_banner_loginwindow_enforce' \
            --recommendation 'Informational only. Review the policy content matches organizational requirements.'
    else
        add_audit_result --category 'Identity, Accounts & Privilege Management' \
            --control 'Password Policy Configured' \
            --status WARN --severity Medium \
            --current 'No explicit password content policy configured' \
            --recommended 'A password content policy is configured' \
            --cis 'CIS 5.2' --nist 'IA-5' --mitre 'T1110 (Brute Force)' --iso27001 'A.8.5' \
            --nis2 'Art.21(2)(i)' --cis-macos 'CIS-macOS 6.4' --mscp 'os_policy_banner_loginwindow_enforce' \
            --recommendation 'Configure a password content policy via "pwpolicy", or deploy one through an MDM Passcode payload.'
    fi
}

check_sudoers_configuration() {
    run_root cat /etc/sudoers

    if [[ $ROOT_CMD_STATUS -ne 0 ]]; then
        add_audit_result --category 'Identity, Accounts & Privilege Management' \
            --control 'Sudoers Configuration' \
            --status WARN --severity Low --current "Unable to read /etc/sudoers: $ROOT_CMD_OUTPUT" \
            --recommended 'No NOPASSWD or !authenticate directives' \
            --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'Unable to read /etc/sudoers; verify manually with "sudo cat /etc/sudoers".'
        return
    fi

    local combined="$ROOT_CMD_OUTPUT"

    run_root find /etc/sudoers.d -maxdepth 1 -type f
    local -a dropin_files
    dropin_files=("${(@f)ROOT_CMD_OUTPUT}")
    local f
    for f in "${dropin_files[@]}"; do
        [[ -z "$f" ]] && continue
        run_root cat "$f"
        combined+=$'\n'"$ROOT_CMD_OUTPUT"
    done

    local -a lines flagged=()
    lines=("${(@f)combined}")
    local line trimmed
    for line in "${lines[@]}"; do
        trimmed="${line## }"
        trimmed="${trimmed##	}"
        [[ -z "$trimmed" || "$trimmed" == \#* ]] && continue
        if [[ "$line" == *NOPASSWD* || "$line" == *'!authenticate'* ]]; then
            flagged+=("$line")
        fi
    done

    if (( ${#flagged[@]} > 0 )); then
        local joined
        joined=$(printf '%s | ' "${flagged[@]}")
        joined="${joined%' | '}"
        add_audit_result --category 'Identity, Accounts & Privilege Management' \
            --control 'Sudoers Configuration' \
            --status WARN --severity Medium --current "$joined" \
            --recommended 'No NOPASSWD or !authenticate directives' \
            --cis 'CIS 5.1' --nist 'AC-6' --mitre 'T1548.003 (Sudo and Sudo Caching)' --iso27001 'A.8.2' \
            --nis2 'Art.21(2)(i)' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'Review each NOPASSWD/!authenticate rule in /etc/sudoers and /etc/sudoers.d/*; either is a common privilege-escalation shortcut for an attacker who gains any shell as that user.'
    else
        add_audit_result --category 'Identity, Accounts & Privilege Management' \
            --control 'Sudoers Configuration' \
            --status PASS --severity Medium --current 'No NOPASSWD or !authenticate directives found' \
            --recommended 'No NOPASSWD or !authenticate directives' \
            --cis 'CIS 5.1' --nist 'AC-6' --mitre 'T1548.003 (Sudo and Sudo Caching)' --iso27001 'A.8.2' \
            --nis2 'Art.21(2)(i)' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'No action required.'
    fi
}

# --- CIS Apple macOS 26 Tahoe v1.0.0 sections 2.6.8, 2.12.1, 2.13.2, 5.2.x, 5.4-5.11 ---

# Prints the integer that follows <key>$name</key> in pwpolicy XML output.
_pwpolicy_param() {
    local xml="$1" name="$2"
    print -r -- "$xml" | awk -v k="<key>$name</key>" '
        index($0, k) { want = 1; next }
        want && match($0, /<integer>[0-9]+<\/integer>/) { v = substr($0, RSTART + 9, RLENGTH - 19); print v; exit }
        want && /<key>/ { want = 0 }'
}

_pwpolicy_fw() {
    # Shared framework flags for the password-policy controls; $1 = CIS-macOS
    # section, $2 = mSCP rule, $3 = CIS Controls v8 safeguard.
    reply=(--cis "CIS $3" --nist 'IA-5(1)' --mitre 'T1110 (Brute Force)' --iso27001 'A.5.17'
           --nis2 'Art.21(2)(i)' --nsa 'NSA/CISA Password Guidance' --cis-macos "CIS-macOS $1" --mscp "$2")
}

_pwpolicy_query_failed() {
    local control="$1"; shift
    add_audit_result --category 'Identity, Accounts & Privilege Management' --control "$control" \
        --status WARN --severity Low --current "pwpolicy query failed: $ROOT_CMD_OUTPUT" "$@" \
        --recommendation 'Verify manually with "sudo pwpolicy -getaccountpolicies".'
}

check_password_lockout_threshold() {
    write_section_banner 'Identity, Accounts & Privilege Management - Password Policy (CIS 5.2)'
    run_root pwpolicy -getaccountpolicies
    _pwpolicy_fw 5.2.1 pwpolicy_account_lockout_enforce 6.2
    local -a fw=("${reply[@]}" --recommended 'policyAttributeMaximumFailedAuthentications <= 5')
    if [[ $ROOT_CMD_STATUS -ne 0 ]]; then
        _pwpolicy_query_failed 'Password Account Lockout Threshold' "${fw[@]}"; return 0
    fi
    local value
    value=$(_pwpolicy_param "$ROOT_CMD_OUTPUT" policyAttributeMaximumFailedAuthentications)
    if [[ "$value" == <-> ]] && (( value > 0 && value <= 5 )); then
        add_audit_result --category 'Identity, Accounts & Privilege Management' --control 'Password Account Lockout Threshold' \
            --status PASS --severity High --current "Lockout after $value failed attempts" "${fw[@]}" \
            --recommendation 'No action required.'
    else
        add_audit_result --category 'Identity, Accounts & Privilege Management' --control 'Password Account Lockout Threshold' \
            --status FAIL --severity High --current "$([[ -n "$value" ]] && print -r -- "Lockout after $value failed attempts" || print -r -- "No lockout threshold configured")" "${fw[@]}" \
            --recommendation 'Set an account lockout threshold of 5 or fewer failed attempts: "sudo pwpolicy -setaccountpolicies" with policyAttributeMaximumFailedAuthentications, or an MDM Passcode payload (maxFailedAttempts).'
    fi
}

check_password_minimum_length() {
    run_root pwpolicy -getaccountpolicies
    _pwpolicy_fw 5.2.2 pwpolicy_minimum_length_enforce 5.2
    local -a fw=("${reply[@]}" --recommended 'Minimum password length >= 15')
    if [[ $ROOT_CMD_STATUS -ne 0 ]]; then
        _pwpolicy_query_failed 'Password Minimum Length' "${fw[@]}"; return 0
    fi
    # Only length rules have the shape ".{N," — complexity rules such as
    # "(.*[0-9].*){1,}" have ")" before the brace and are excluded.
    local value
    value=$(print -r -- "$ROOT_CMD_OUTPUT" | grep -oE "policyAttributePassword matches '\^?\.\{[0-9]+," \
        | grep -oE '[0-9]+' | sort -n | tail -1)
    if [[ "$value" == <-> ]] && (( value >= 15 )); then
        add_audit_result --category 'Identity, Accounts & Privilege Management' --control 'Password Minimum Length' \
            --status PASS --severity High --current "Minimum length $value" "${fw[@]}" \
            --recommendation 'No action required.'
    else
        add_audit_result --category 'Identity, Accounts & Privilege Management' --control 'Password Minimum Length' \
            --status FAIL --severity High --current "$([[ -n "$value" ]] && print -r -- "Minimum length $value" || print -r -- "No minimum length policy configured")" "${fw[@]}" \
            --recommendation 'Require passwords of at least 15 characters via "sudo pwpolicy -setaccountpolicies" or an MDM Passcode payload (minLength).'
    fi
}

check_password_age() {
    run_root pwpolicy -getaccountpolicies
    _pwpolicy_fw 5.2.7 pwpolicy_max_lifetime_enforce 5.3
    local -a fw=("${reply[@]}" --recommended 'Password expires within 365 days')
    if [[ $ROOT_CMD_STATUS -ne 0 ]]; then
        _pwpolicy_query_failed 'Password Age' "${fw[@]}"; return 0
    fi
    local every until
    every=$(_pwpolicy_param "$ROOT_CMD_OUTPUT" policyAttributeExpiresEveryNDays)
    until=$(_pwpolicy_param "$ROOT_CMD_OUTPUT" policyAttributeDaysUntilExpiration)
    local current="ExpiresEveryNDays=${every:-not set}, DaysUntilExpiration=${until:-not set}"
    if { [[ "$every" == <-> ]] && (( every > 0 && every <= 365 )); } || { [[ "$until" == <-> ]] && (( until > 0 && until <= 365 )); }; then
        add_audit_result --category 'Identity, Accounts & Privilege Management' --control 'Password Age' \
            --status PASS --severity Low --current "$current" "${fw[@]}" --recommendation 'No action required.'
    else
        add_audit_result --category 'Identity, Accounts & Privilege Management' --control 'Password Age' \
            --status FAIL --severity Low --current "$current" "${fw[@]}" \
            --recommendation 'Set a maximum password age of 365 days or less via "sudo pwpolicy -setaccountpolicies" or an MDM Passcode payload (maxPINAgeInDays).'
    fi
}

check_password_history() {
    run_root pwpolicy -getaccountpolicies
    _pwpolicy_fw 5.2.8 pwpolicy_history_enforce 5.2
    local -a fw=("${reply[@]}" --recommended 'policyAttributePasswordHistoryDepth >= 24')
    if [[ $ROOT_CMD_STATUS -ne 0 ]]; then
        _pwpolicy_query_failed 'Password History' "${fw[@]}"; return 0
    fi
    # Threshold follows the recommendation title (">= 24", also mSCP's
    # value); the benchmark's own audit one-liner only tests ">= 1".
    local value
    value=$(_pwpolicy_param "$ROOT_CMD_OUTPUT" policyAttributePasswordHistoryDepth)
    if [[ "$value" == <-> ]] && (( value >= 24 )); then
        add_audit_result --category 'Identity, Accounts & Privilege Management' --control 'Password History' \
            --status PASS --severity Medium --current "Last $value passwords remembered" "${fw[@]}" \
            --recommendation 'No action required.'
    else
        add_audit_result --category 'Identity, Accounts & Privilege Management' --control 'Password History' \
            --status FAIL --severity Medium --current "$([[ -n "$value" ]] && print -r -- "Last $value passwords remembered" || print -r -- "No password history policy configured")" "${fw[@]}" \
            --recommendation 'Prevent reuse of the last 24 passwords via "sudo pwpolicy -setaccountpolicies" or an MDM Passcode payload (pinHistory).'
    fi
}

# Evaluates one line of "sudo -V" (run as root, which prints the
# effective sudoers defaults). Parameterized: control, expected
# substring, CIS section, mSCP rule, recommendation.
_sudo_default_check() {
    local control="$1" needle="$2" cis_macos="$3" mscp_id="$4" recommendation="$5" current_label="$6"
    run_root sudo -V
    local -a fw
    fw=(--recommended "$needle" --cis 'CIS 4.3' --nist 'AC-6, AU-12' --mitre 'T1548.003 (Sudo and Sudo Caching)'
        --iso27001 'A.8.2' --nis2 'Art.21(2)(i)' --cis-macos "CIS-macOS $cis_macos" --mscp "$mscp_id")

    if [[ $ROOT_CMD_STATUS -ne 0 || "$ROOT_CMD_OUTPUT" != *"Sudoers policy"* ]]; then
        add_audit_result --category 'Identity, Accounts & Privilege Management' --control "$control" \
            --status WARN --severity Low --current "sudo -V query failed or returned no policy details" "${fw[@]}" \
            --recommendation 'Verify manually with "sudo sudo -V".'
        return 0
    fi

    local line
    line=$(print -r -- "$ROOT_CMD_OUTPUT" | grep -F "$current_label" | head -1 | sed 's/^[[:space:]]*//')
    if [[ "$ROOT_CMD_OUTPUT" == *"$needle"* ]]; then
        add_audit_result --category 'Identity, Accounts & Privilege Management' --control "$control" \
            --status PASS --severity Medium --current "$needle" "${fw[@]}" --recommendation 'No action required.'
    else
        add_audit_result --category 'Identity, Accounts & Privilege Management' --control "$control" \
            --status FAIL --severity Medium --current "${line:-Setting not present in sudo -V output}" "${fw[@]}" \
            --recommendation "$recommendation"
    fi
}

check_sudo_timeout_zero() {
    _sudo_default_check 'Sudo Timeout Period' 'Authentication timestamp timeout: 0.0 minutes' 5.4 \
        os_sudo_timeout_configure \
        'Add "Defaults timestamp_timeout=0" in a file under /etc/sudoers.d/ (edit with "sudo visudo -f /etc/sudoers.d/10_cissudoconfiguration") so every sudo use re-authenticates.' \
        'Authentication timestamp timeout'
}

check_sudo_timestamp_per_tty() {
    _sudo_default_check 'Sudo Separate Timestamp per TTY' 'Type of authentication timestamp record: tty' 5.5 \
        os_sudoers_timestamp_type_configure \
        'Add "Defaults timestamp_type=tty" in a file under /etc/sudoers.d/ (via "sudo visudo -f") so a sudo ticket in one terminal is not reusable from another.' \
        'Type of authentication timestamp record'
}

check_sudo_logging_enabled() {
    _sudo_default_check 'Sudo Command Logging' 'Log when a command is allowed by sudoers' 5.11 \
        os_sudo_log_enforce \
        'Add "Defaults log_allowed" in a file under /etc/sudoers.d/ (via "sudo visudo -f") so successful sudo commands are logged.' \
        'Log when a command is allowed'
}

_authdb_value() {
    print -r -- "$1" | plutil -extract "$2" raw -o - - 2>/dev/null
}

check_admin_password_for_system_preferences() {
    local -a rights
    rights=(system.preferences system.preferences.energysaver system.preferences.network system.preferences.printing
            system.preferences.sharing system.preferences.softwareupdate system.preferences.startupdisk
            system.preferences.timemachine)
    local -a fw
    fw=(--recommended 'shared=false, group=admin, authenticate-user=true, session-owner=false for every system.preferences right'
        --cis 'CIS 4.1' --nist 'AC-6, CM-5' --mitre 'T1548 (Abuse Elevation Control Mechanism)' --iso27001 'A.8.2'
        --nis2 'Art.21(2)(i)' --cis-macos 'CIS-macOS 2.6.8' --mscp 'system_settings_system_wide_preferences_configure')

    local right xml failed_queries=0
    local -a noncompliant
    for right in "${rights[@]}"; do
        run_root security -q authorizationdb read "$right"
        if [[ $ROOT_CMD_STATUS -ne 0 ]]; then
            failed_queries=$((failed_queries + 1)); continue
        fi
        xml="$ROOT_CMD_OUTPUT"
        if [[ "$(_authdb_value "$xml" shared)" != "false" || "$(_authdb_value "$xml" group)" != "admin" \
              || "$(_authdb_value "$xml" authenticate-user)" != "true" || "$(_authdb_value "$xml" session-owner)" != "false" ]]; then
            noncompliant+=("$right")
        fi
    done

    if [[ $failed_queries -eq ${#rights[@]} ]]; then
        add_audit_result --category 'Identity, Accounts & Privilege Management' --control 'Admin Password Required for System-Wide Preferences' \
            --status WARN --severity Low --current 'authorizationdb queries failed' "${fw[@]}" \
            --recommendation 'Verify manually with "security authorizationdb read system.preferences".'
    elif [[ ${#noncompliant[@]} -eq 0 ]]; then
        add_audit_result --category 'Identity, Accounts & Privilege Management' --control 'Admin Password Required for System-Wide Preferences' \
            --status PASS --severity Medium --current 'All system.preferences rights require an admin password' "${fw[@]}" \
            --recommendation 'No action required.'
    else
        add_audit_result --category 'Identity, Accounts & Privilege Management' --control 'Admin Password Required for System-Wide Preferences' \
            --status FAIL --severity Medium --current "${#noncompliant[@]} of ${#rights[@]} rights not locked to admin authentication" \
            --details "${(F)noncompliant}" "${fw[@]}" \
            --recommendation 'For each listed right, set shared=false (and require admin auth) with "security authorizationdb read <right> > r.plist", edit, then "sudo security authorizationdb write <right> < r.plist" — or deploy via MDM.'
    fi
}

check_admin_cannot_unlock_other_sessions() {
    run_root security -q authorizationdb read system.login.screensaver
    local xml="$ROOT_CMD_OUTPUT" xml_status=$ROOT_CMD_STATUS
    local -a fw
    fw=(--recommended 'system.login.screensaver rule = authenticate-session-owner' --cis 'CIS 4.3' --nist 'AC-11, AC-6'
        --mitre 'T1078.003 (Local Accounts)' --iso27001 'A.8.5' --nis2 'Art.21(2)(i)'
        --cis-macos 'CIS-macOS 5.7' --mscp 'os_unlock_active_user_session_disable')

    if [[ $xml_status -ne 0 ]]; then
        add_audit_result --category 'Identity, Accounts & Privilege Management' --control 'Admin Cannot Unlock Other User Sessions' \
            --status WARN --severity Low --current "authorizationdb query failed: $xml" "${fw[@]}" \
            --recommendation 'Verify manually with "security authorizationdb read system.login.screensaver".'
        return 0
    fi

    local rule
    rule=$(print -r -- "$xml" | plutil -extract rule json -o - - 2>/dev/null)
    if [[ "$rule" == *'"authenticate-session-owner"'* ]]; then
        add_audit_result --category 'Identity, Accounts & Privilege Management' --control 'Admin Cannot Unlock Other User Sessions' \
            --status PASS --severity Medium --current "rule = $rule" "${fw[@]}" --recommendation 'No action required.'
        return 0
    fi

    # CIS: when Platform SSO is configured this right is managed by the
    # IdP integration and must not be remediated — report, don't score.
    run_root app-sso platform -s
    local device_config
    device_config=$(print -r -- "$ROOT_CMD_OUTPUT" | awk '/^Device Configuration:/{getline; gsub(/^[ \t]+/, ""); print; exit}')
    if [[ $ROOT_CMD_STATUS -eq 0 && -n "$device_config" && "$device_config" != "(null)" ]]; then
        add_audit_result --category 'Identity, Accounts & Privilege Management' --control 'Admin Cannot Unlock Other User Sessions' \
            --status INFO --severity Informational --current "rule = ${rule:-unknown}; Platform SSO is configured" "${fw[@]}" \
            --recommendation 'Platform SSO manages this right; per CIS, do not apply the remediation on PSSO-enrolled Macs.'
    else
        add_audit_result --category 'Identity, Accounts & Privilege Management' --control 'Admin Cannot Unlock Other User Sessions' \
            --status FAIL --severity Medium --current "rule = ${rule:-unknown}" "${fw[@]}" \
            --recommendation 'Restrict screensaver unlock to the session owner: "sudo security authorizationdb write system.login.screensaver authenticate-session-owner".'
    fi
}

check_user_password_hints_absent() {
    run_root dscl . -list /Users hint
    local -a fw
    fw=(--recommended 'No local account has a password hint' --cis 'CIS 5.2' --nist 'IA-5, IA-6'
        --mitre 'T1110 (Brute Force)' --iso27001 'A.5.17' --nis2 'Art.21(2)(i)'
        --cis-macos 'CIS-macOS 2.12.1' --mscp 'os_password_hint_remove')

    if [[ $ROOT_CMD_STATUS -ne 0 ]]; then
        add_audit_result --category 'Identity, Accounts & Privilege Management' --control 'User Password Hints' \
            --status WARN --severity Low --current "dscl query failed: $ROOT_CMD_OUTPUT" "${fw[@]}" \
            --recommendation 'Verify manually with "sudo dscl . -list /Users hint".'
        return 0
    fi

    # Only usernames are reported, never the hint text itself.
    local -a with_hint
    with_hint=(${(f)"$(print -r -- "$ROOT_CMD_OUTPUT" | awk 'NF >= 2 {print $1}')"})
    if [[ ${#with_hint[@]} -eq 0 ]]; then
        add_audit_result --category 'Identity, Accounts & Privilege Management' --control 'User Password Hints' \
            --status PASS --severity Medium --current 'No account has a password hint' "${fw[@]}" \
            --recommendation 'No action required.'
    else
        add_audit_result --category 'Identity, Accounts & Privilege Management' --control 'User Password Hints' \
            --status FAIL --severity Medium --current "${#with_hint[@]} account(s) have a password hint" \
            --details "${(F)with_hint}" "${fw[@]}" \
            --recommendation 'Remove each hint: "sudo dscl . -delete /Users/<username> hint".'
    fi
}

check_smb_guest_access_disabled() {
    run_root sysadminctl -smbGuestAccess status
    local -a fw
    fw=(--recommended 'SMB guest access disabled' --cis 'CIS 3.3' --nist 'AC-14, AC-3'
        --mitre 'T1021.002 (SMB/Windows Admin Shares)' --iso27001 'A.8.3' --nis2 'Art.21(2)(i)'
        --cis-macos 'CIS-macOS 2.13.2' --mscp 'system_settings_guest_access_smb_disable')

    if [[ "$ROOT_CMD_OUTPUT" == *"SMB guest access disabled"* ]]; then
        add_audit_result --category 'Identity, Accounts & Privilege Management' --control 'Guest Access to Shared Folders' \
            --status PASS --severity High --current 'SMB guest access disabled' "${fw[@]}" --recommendation 'No action required.'
    elif [[ "$ROOT_CMD_OUTPUT" == *"SMB guest access enabled"* ]]; then
        add_audit_result --category 'Identity, Accounts & Privilege Management' --control 'Guest Access to Shared Folders' \
            --status FAIL --severity High --current 'SMB guest access enabled' "${fw[@]}" \
            --recommendation 'Disable unauthenticated access to shared folders: "sudo sysadminctl -smbGuestAccess off".'
    else
        add_audit_result --category 'Identity, Accounts & Privilege Management' --control 'Guest Access to Shared Folders' \
            --status WARN --severity Low --current "Query failed or unrecognized output: $ROOT_CMD_OUTPUT" "${fw[@]}" \
            --recommendation 'Verify manually with "sudo sysadminctl -smbGuestAccess status".'
    fi
}

# Parameterized on the folder path so it is testable against a scratch dir.
_guest_home_folder_check() {
    local guest_home="$1"
    local -a fw
    fw=(--recommended 'No Guest home folder' --cis 'CIS 4.1' --nist 'AC-2' --iso27001 'A.5.18'
        --nis2 'Art.21(2)(i)' --cis-macos 'CIS-macOS 5.9' --mscp 'os_guest_folder_removed')
    if [[ -d "$guest_home" ]]; then
        add_audit_result --category 'Identity, Accounts & Privilege Management' --control 'Guest Home Folder Removed' \
            --status FAIL --severity Low --current "$guest_home exists" "${fw[@]}" \
            --recommendation "With the Guest account disabled, remove the leftover folder after reviewing its contents: sudo rm -R $guest_home"
    else
        add_audit_result --category 'Identity, Accounts & Privilege Management' --control 'Guest Home Folder Removed' \
            --status PASS --severity Low --current 'No Guest home folder' "${fw[@]}" --recommendation 'No action required.'
    fi
}

check_guest_home_folder_absent() {
    _guest_home_folder_check /Users/Guest
}

# ---- 17-firewall.zsh ----
#
# Domain 8: Network Firewall & Packet Filtering

: ${SOCKETFILTERFW:=/usr/libexec/ApplicationFirewall/socketfilterfw}

check_firewall_state() {
    write_section_banner 'Network Firewall & Packet Filtering - Firewall State'
    run_root "$SOCKETFILTERFW" --getglobalstate

    if [[ "$ROOT_CMD_OUTPUT" == *"enabled"* ]]; then
        add_audit_result --category 'Network Firewall & Packet Filtering' --control 'Firewall State' \
            --status PASS --severity High --current "$ROOT_CMD_OUTPUT" \
            --recommended 'Firewall enabled' \
            --cis 'CIS 4.1' --nist 'SC-7' --mitre 'T1562.004 (Disable or Modify System Firewall)' --iso27001 'A.8.20' \
            --nis2 'Art.21(2)(d)' --nsa 'NSA/CISA macOS Hardening Guidance' --cis-macos 'CIS-macOS 2.4.1' --mscp 'os_firewall_enable' \
            --recommendation 'No action required.'
    elif [[ "$ROOT_CMD_OUTPUT" == *"disabled"* ]]; then
        add_audit_result --category 'Network Firewall & Packet Filtering' --control 'Firewall State' \
            --status FAIL --severity High --current "$ROOT_CMD_OUTPUT" \
            --recommended 'Firewall enabled' \
            --cis 'CIS 4.1' --nist 'SC-7' --mitre 'T1562.004 (Disable or Modify System Firewall)' --iso27001 'A.8.20' \
            --nis2 'Art.21(2)(d)' --nsa 'NSA/CISA macOS Hardening Guidance' --cis-macos 'CIS-macOS 2.4.1' --mscp 'os_firewall_enable' \
            --recommendation 'Enable the firewall: System Settings > Network > Firewall, or "sudo \"$SOCKETFILTERFW\" --setglobalstate on".'
    else
        # Fault isolation: a failing/unrecognized query must never be
        # reported identically to a verified-enabled or verified-disabled
        # firewall state above.
        add_audit_result --category 'Network Firewall & Packet Filtering' --control 'Firewall State' \
            --status WARN --severity Low --current "Query failed or unrecognized output: $ROOT_CMD_OUTPUT" \
            --recommended 'Firewall enabled' \
            --cis 'CIS 4.1' --nist 'SC-7' --cis-macos 'CIS-macOS 2.4.1' --mscp 'os_firewall_enable' \
            --recommendation 'Unable to determine firewall state; verify manually with "socketfilterfw --getglobalstate".'
    fi
}

check_firewall_stealth_mode() {
    run_root "$SOCKETFILTERFW" --getstealthmode

    if [[ "$ROOT_CMD_OUTPUT" == *"enabled"* ]]; then
        add_audit_result --category 'Network Firewall & Packet Filtering' --control 'Firewall Stealth Mode' \
            --status PASS --severity Medium --current "$ROOT_CMD_OUTPUT" \
            --recommended 'Stealth mode enabled' \
            --cis 'CIS 4.1' --nist 'SC-7' --mitre 'T1046 (Network Service Discovery)' --iso27001 'A.8.20' \
            --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 2.4.2' --mscp 'os_firewall_stealth_mode_enable' \
            --recommendation 'No action required.'
    elif [[ "$ROOT_CMD_OUTPUT" == *"disabled"* ]]; then
        add_audit_result --category 'Network Firewall & Packet Filtering' --control 'Firewall Stealth Mode' \
            --status WARN --severity Medium --current "$ROOT_CMD_OUTPUT" \
            --recommended 'Stealth mode enabled' \
            --cis 'CIS 4.1' --nist 'SC-7' --mitre 'T1046 (Network Service Discovery)' --iso27001 'A.8.20' \
            --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 2.4.2' --mscp 'os_firewall_stealth_mode_enable' \
            --recommendation 'Enable stealth mode: "sudo \"$SOCKETFILTERFW\" --setstealthmode on".'
    else
        # Fault isolation: a failing/unrecognized query is a distinct,
        # lower-confidence WARN from the explicit "disabled" branch above.
        add_audit_result --category 'Network Firewall & Packet Filtering' --control 'Firewall Stealth Mode' \
            --status WARN --severity Low --current "Query failed or unrecognized output: $ROOT_CMD_OUTPUT" \
            --recommended 'Stealth mode enabled' \
            --cis 'CIS 4.1' --nist 'SC-7' --cis-macos 'CIS-macOS 2.4.2' --mscp 'os_firewall_stealth_mode_enable' \
            --recommendation 'Unable to determine stealth mode state; verify manually with "socketfilterfw --getstealthmode".'
    fi
}

check_firewall_block_all_incoming() {
    run_root "$SOCKETFILTERFW" --getblockall

    # Always INFO: blocking all incoming is stricter but breaks legitimate
    # sharing use cases — environment-dependent, not a judgement.
    add_audit_result --category 'Network Firewall & Packet Filtering' --control 'Block All Incoming Connections' \
        --status INFO --severity Informational --current "$ROOT_CMD_OUTPUT" \
        --recommended 'N/A' --cis-macos 'CIS-macOS 2.4.1' --mscp 'N/A' \
        --recommendation 'Informational only. Whether to block all incoming connections depends on whether this Mac needs to offer any sharing services.'
}

check_firewall_signed_app_auto_allow() {
    run_root "$SOCKETFILTERFW" --getallowsigned

    # Always INFO: Apple's default of auto-allowing signed built-in
    # software is expected behavior, not a misconfiguration.
    add_audit_result --category 'Network Firewall & Packet Filtering' --control 'Signed Application Auto-Allow' \
        --status INFO --severity Informational --current "$ROOT_CMD_OUTPUT" \
        --recommended 'N/A' --cis-macos 'CIS-macOS 2.4.1' --mscp 'N/A' \
        --recommendation 'Informational only. Auto-allowing signed built-in software is expected default behavior.'
}

check_firewall_per_app_exceptions() {
    run_root "$SOCKETFILTERFW" --listapps

    local count_line count=""
    count_line=$(print -r -- "$ROOT_CMD_OUTPUT" | grep -m1 'Total number of apps')
    local -a words
    words=(${(z)count_line})
    (( ${#words[@]} > 0 )) && count="${words[-1]}"

    if [[ ! "$count" =~ '^[0-9]+$' ]]; then
        # Fault isolation: an unparseable count must never be silently
        # reported as "0 app(s)".
        add_audit_result --category 'Network Firewall & Packet Filtering' --control 'Per-App Firewall Exceptions' \
            --status WARN --severity Low --current "Query failed or unrecognized output: $ROOT_CMD_OUTPUT" \
            --recommended 'N/A' --cis-macos 'CIS-macOS 2.4.1' --mscp 'N/A' \
            --recommendation 'Unable to determine per-app firewall exceptions; verify manually with "socketfilterfw --listapps".'
        return
    fi

    # Real "--listapps" output (verified live): each entry is a line
    # "N : <path>" followed by a separate "(Allow/Block incoming
    # connections)" line — extract the path from the "N : " lines and
    # take its basename for the hover list.
    local -a lines names=()
    lines=("${(@f)ROOT_CMD_OUTPUT}")
    # app_path, not "path": zsh ties the scalar $PATH to the array
    # $path, and a plain "local path=..." would shadow that array for
    # this call's entire dynamic scope, breaking bare-name external-
    # command lookup for anything called during it (confirmed live: it
    # broke "date" inside add_audit_result itself). Same class of bug
    # already found and fixed twice elsewhere in this codebase.
    local l app_path
    for l in "${lines[@]}"; do
        [[ "$l" =~ '^[0-9]+ : ' ]] || continue
        app_path="${l#*: }"
        app_path="${app_path% }"
        names+=("${app_path:t}")
    done
    local joined
    joined=$(printf '%s\n' "${names[@]}")

    # Always INFO: this is inventory, not a judgement — a per-app
    # exception is a normal, expected way to allow a specific
    # application through the firewall.
    add_audit_result --category 'Network Firewall & Packet Filtering' --control 'Per-App Firewall Exceptions' \
        --status INFO --severity Informational --current "$count app(s) with a firewall exception configured" \
        --details "$joined" \
        --recommended 'N/A' --cis-macos 'CIS-macOS 2.4.1' --mscp 'N/A' \
        --recommendation 'Informational only. Review the per-app exception list periodically for unrecognized or stale entries.'
}

# Baseline entries every stock macOS /etc/hosts ships with — anything
# else is a real, non-comment mapping worth flagging.
_is_baseline_hosts_entry() {
    local line="$1"
    case "$line" in
        *localhost) return 0 ;;
        *broadcasthost) return 0 ;;
        *) return 1 ;;
    esac
}

check_etc_hosts_integrity() {
    run_root cat /etc/hosts

    if [[ $ROOT_CMD_STATUS -ne 0 ]]; then
        add_audit_result --category 'Network Firewall & Packet Filtering' --control 'Hosts File Integrity' \
            --status WARN --severity Low --current "Unable to read /etc/hosts: $ROOT_CMD_OUTPUT" \
            --recommended 'No non-baseline entries in /etc/hosts' \
            --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'Unable to read /etc/hosts; verify manually with "cat /etc/hosts".'
        return
    fi

    local -a lines extra=()
    lines=("${(@f)ROOT_CMD_OUTPUT}")
    local line trimmed
    for line in "${lines[@]}"; do
        trimmed="${line## }"
        trimmed="${trimmed##	}"
        [[ -z "$trimmed" || "$trimmed" == \#* ]] && continue
        _is_baseline_hosts_entry "$trimmed" || extra+=("$trimmed")
    done

    if (( ${#extra[@]} > 0 )); then
        local joined
        joined=$(printf '%s | ' "${extra[@]}")
        joined="${joined%' | '}"
        add_audit_result --category 'Network Firewall & Packet Filtering' --control 'Hosts File Integrity' \
            --status WARN --severity Medium --current "$joined" \
            --recommended 'No non-baseline entries in /etc/hosts' \
            --cis 'CIS 4.9' --nist 'CM-6' --mitre 'T1565.001 (Stored Data Manipulation)' --iso27001 'A.8.20' \
            --nis2 'Art.21(2)(d)' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'Review each non-baseline /etc/hosts entry — a redirected domain (e.g. pointing an update server at a bogus IP) or a wildcard block is a common tampering technique.'
    else
        add_audit_result --category 'Network Firewall & Packet Filtering' --control 'Hosts File Integrity' \
            --status PASS --severity Medium --current 'Only baseline entries present' \
            --recommended 'No non-baseline entries in /etc/hosts' \
            --cis 'CIS 4.9' --nist 'CM-6' --mitre 'T1565.001 (Stored Data Manipulation)' --iso27001 'A.8.20' \
            --nis2 'Art.21(2)(d)' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'No action required.'
    fi
}

# ---- 18-remote-access.zsh ----
#
# Domain 9: Remote Access & Sharing Services

# Shared "is this launchd service loaded" check for the three sharing
# services that all follow the identical launchctl-print pattern.
# Independently testable: pass any service label/control-name pair.
_launchd_service_enabled_check() {
    local service_label="$1" control_name="$2"
    local mitre cis_macos mscp_id nsa

    case "$control_name" in
        'Screen Sharing')
            mitre='T1021.005 (VNC)'; cis_macos='CIS-macOS 2.5.2'
            mscp_id='os_screen_sharing_disable'; nsa='NSA/CISA macOS Hardening Guidance' ;;
        'Remote Management (ARD)')
            mitre='T1021.005 (VNC)'; cis_macos='CIS-macOS 2.5.2'
            mscp_id='os_remote_management_disable'; nsa='NSA/CISA macOS Hardening Guidance' ;;
        'File Sharing (SMB)')
            mitre='T1021.002 (SMB/Windows Admin Shares)'; cis_macos='CIS-macOS 2.5.1'
            mscp_id='os_file_sharing_disable'; nsa='N/A' ;;
        *)
            mitre='N/A'; cis_macos='N/A'; mscp_id='N/A'; nsa='N/A' ;;
    esac

    run_root launchctl print "system/$service_label"

    if [[ $ROOT_CMD_STATUS -eq 0 ]]; then
        add_audit_result --category 'Remote Access & Sharing Services' --control "$control_name" \
            --status WARN --severity Medium --current "$control_name is enabled" \
            --recommended "$control_name is disabled" \
            --cis 'CIS 4.9' --nist 'AC-17, SC-7' --mitre "$mitre" --iso27001 'A.8.20' \
            --nis2 'Art.21(2)(d)' --nsa "$nsa" --cis-macos "$cis_macos" --mscp "$mscp_id" \
            --recommendation "Disable $control_name in System Settings > General > Sharing unless remote support is an intentional, documented requirement."
    else
        add_audit_result --category 'Remote Access & Sharing Services' --control "$control_name" \
            --status PASS --severity Medium --current "$control_name is disabled" \
            --recommended "$control_name is disabled" \
            --cis 'CIS 4.9' --nist 'AC-17, SC-7' --mitre "$mitre" --iso27001 'A.8.20' \
            --nis2 'Art.21(2)(d)' --nsa "$nsa" --cis-macos "$cis_macos" --mscp "$mscp_id" \
            --recommendation 'No action required.'
    fi
}

check_screen_sharing_state() {
    write_section_banner 'Remote Access & Sharing Services - Screen Sharing State'
    _launchd_service_enabled_check com.apple.screensharing 'Screen Sharing'
}

check_remote_management_state() {
    _launchd_service_enabled_check com.apple.RemoteDesktop.agent 'Remote Management (ARD)'
}

check_file_sharing_state() {
    _launchd_service_enabled_check com.apple.smbd 'File Sharing (SMB)'
}

check_remote_login_toggle() {
    run_root systemsetup -getremotelogin

    if [[ "$ROOT_CMD_OUTPUT" == *"On"* ]]; then
        add_audit_result --category 'Remote Access & Sharing Services' --control 'Remote Login (SSH) Toggle' \
            --status WARN --severity Medium --current 'Remote Login: On' \
            --recommended 'Remote Login: Off' \
            --cis 'CIS 4.9' --nist 'AC-17' --mitre 'T1021.004 (SSH)' --iso27001 'A.8.20' \
            --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 2.5.3' --mscp 'os_ssh_server_disable' \
            --recommendation 'Disable via System Settings > General > Sharing > Remote Login unless SSH access is required (see the SSH Server & Client Hardening domain for hardening if it is), or "sudo systemsetup -setremotelogin off".'
    elif [[ "$ROOT_CMD_OUTPUT" == *"Off"* ]]; then
        add_audit_result --category 'Remote Access & Sharing Services' --control 'Remote Login (SSH) Toggle' \
            --status PASS --severity Medium --current 'Remote Login: Off' \
            --recommended 'Remote Login: Off' \
            --cis 'CIS 4.9' --nist 'AC-17' --mitre 'T1021.004 (SSH)' --iso27001 'A.8.20' \
            --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 2.5.3' --mscp 'os_ssh_server_disable' \
            --recommendation 'No action required.'
    else
        # Fault isolation: a failing/unrecognized query must never be
        # reported identically to a verified "Off" result above.
        add_audit_result --category 'Remote Access & Sharing Services' --control 'Remote Login (SSH) Toggle' \
            --status WARN --severity Low --current "Query failed or unrecognized output: $ROOT_CMD_OUTPUT" \
            --recommended 'Remote Login: Off' \
            --cis 'CIS 4.9' --nist 'AC-17' --cis-macos 'CIS-macOS 2.5.3' --mscp 'os_ssh_server_disable' \
            --recommendation 'Unable to determine remote login state; verify manually with "systemsetup -getremotelogin".'
    fi
}

# --- CIS Apple macOS 26 Tahoe v1.0.0 sections 2.3.1.2 and 2.3.3.x ---

check_airplay_receiver_disabled() {
    evaluate_managed_pref --category 'Remote Access & Sharing Services' --control 'AirPlay Receiver Disabled' \
        --severity Medium --suite com.apple.applicationaccess --key allowAirPlayIncomingRequests --expect 0 \
        --cis 'CIS 4.1, 4.8' --nist 'CM-7, SC-7' --mitre 'T1021 (Remote Services)' --iso27001 'A.8.20' \
        --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 2.3.1.2' --mscp 'system_settings_airplay_receiver_disable' \
        --recommendation 'Deploy a Restrictions profile with allowAirPlayIncomingRequests=false so the Mac does not listen for AirPlay connections.'
}

check_printer_sharing_disabled() {
    run_root cupsctl
    local -a fw
    fw=(--recommended '_share_printers=0' --cis 'CIS 4.1, 4.8' --nist 'CM-7, SC-7' --iso27001 'A.8.20'
        --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 2.3.3.3' --mscp 'system_settings_printer_sharing_disable')

    if [[ $ROOT_CMD_STATUS -ne 0 ]]; then
        add_audit_result --category 'Remote Access & Sharing Services' --control 'Printer Sharing' \
            --status WARN --severity Low --current "cupsctl query failed: $ROOT_CMD_OUTPUT" "${fw[@]}" \
            --recommendation 'Verify manually in System Settings > General > Sharing > Printer Sharing.'
    elif [[ "$ROOT_CMD_OUTPUT" == *"_share_printers=0"* ]]; then
        add_audit_result --category 'Remote Access & Sharing Services' --control 'Printer Sharing' \
            --status PASS --severity Medium --current 'Printer Sharing is disabled' "${fw[@]}" \
            --recommendation 'No action required.'
    else
        add_audit_result --category 'Remote Access & Sharing Services' --control 'Printer Sharing' \
            --status FAIL --severity Medium --current 'Printer Sharing is enabled' "${fw[@]}" \
            --recommendation 'Disable Printer Sharing: "sudo cupsctl --no-share-printers", or System Settings > General > Sharing.'
    fi
}

check_remote_apple_events_disabled() {
    run_root systemsetup -getremoteappleevents
    local -a fw
    fw=(--recommended 'Remote Apple Events: Off' --cis 'CIS 4.1, 4.8' --nist 'AC-17, CM-7'
        --mitre 'T1021 (Remote Services)' --iso27001 'A.8.20' --nis2 'Art.21(2)(d)'
        --cis-macos 'CIS-macOS 2.3.3.6' --mscp 'system_settings_rae_disable')

    if [[ "$ROOT_CMD_OUTPUT" == *"Remote Apple Events: Off"* ]]; then
        add_audit_result --category 'Remote Access & Sharing Services' --control 'Remote Apple Events' \
            --status PASS --severity High --current 'Remote Apple Events: Off' "${fw[@]}" \
            --recommendation 'No action required.'
    elif [[ "$ROOT_CMD_OUTPUT" == *"Remote Apple Events: On"* ]]; then
        add_audit_result --category 'Remote Access & Sharing Services' --control 'Remote Apple Events' \
            --status FAIL --severity High --current 'Remote Apple Events: On' "${fw[@]}" \
            --recommendation 'Disable Remote Apple Events (lets remote hosts send AppleScript events to this Mac): System Settings > General > Sharing, or "sudo systemsetup -setremoteappleevents off".'
    else
        add_audit_result --category 'Remote Access & Sharing Services' --control 'Remote Apple Events' \
            --status WARN --severity Low --current "Query failed or unrecognized output: $ROOT_CMD_OUTPUT" "${fw[@]}" \
            --recommendation 'Verify manually in System Settings > General > Sharing > Remote Application Scripting.'
    fi
}

check_internet_sharing_disabled() {
    local forced_off
    forced_off=$(managed_pref_read com.apple.MCX forceInternetSharingOff)
    run_root defaults read /Library/Preferences/SystemConfiguration/com.apple.nat
    local -a fw
    fw=(--recommended 'Internet Sharing not enabled (or forceInternetSharingOff=true)' --cis 'CIS 4.1, 4.8'
        --nist 'SC-7, CM-7' --mitre 'T1090 (Proxy)' --iso27001 'A.8.20' --nis2 'Art.21(2)(d)'
        --cis-macos 'CIS-macOS 2.3.3.7' --mscp 'system_settings_internet_sharing_disable')

    # A missing com.apple.nat domain is the normal state when Internet
    # Sharing has never been turned on — CIS counts that as compliant.
    if [[ "$forced_off" == "1" ]]; then
        add_audit_result --category 'Remote Access & Sharing Services' --control 'Internet Sharing' \
            --status PASS --severity High --current 'Disabled by configuration profile (forceInternetSharingOff)' "${fw[@]}" \
            --recommendation 'No action required.'
    elif [[ $ROOT_CMD_STATUS -eq 0 && "$ROOT_CMD_OUTPUT" == *"Enabled = 1;"* ]]; then
        add_audit_result --category 'Remote Access & Sharing Services' --control 'Internet Sharing' \
            --status FAIL --severity High --current 'Internet Sharing is enabled (com.apple.nat Enabled = 1)' "${fw[@]}" \
            --recommendation 'Disable Internet Sharing in System Settings > General > Sharing; it turns this Mac into a router bridging networks.'
    elif [[ $ROOT_CMD_STATUS -eq 0 || "$ROOT_CMD_OUTPUT" == *"does not exist"* || "$ROOT_CMD_OUTPUT" == *"not found"* ]]; then
        add_audit_result --category 'Remote Access & Sharing Services' --control 'Internet Sharing' \
            --status PASS --severity High --current 'Internet Sharing is not enabled' "${fw[@]}" \
            --recommendation 'No action required.'
    else
        add_audit_result --category 'Remote Access & Sharing Services' --control 'Internet Sharing' \
            --status WARN --severity Low --current "com.apple.nat query failed: $ROOT_CMD_OUTPUT" "${fw[@]}" \
            --recommendation 'Verify manually in System Settings > General > Sharing > Internet Sharing.'
    fi
}

check_content_caching_disabled() {
    local activated allowed
    activated=$(managed_pref_read com.apple.AssetCache Activated)
    allowed=$(managed_pref_read com.apple.applicationaccess allowContentCaching)
    local current="AssetCache Activated=${activated:-not set}, allowContentCaching=${allowed:-not set}"
    local -a fw
    fw=(--recommended 'Activated=0 or allowContentCaching=false' --cis 'CIS 4.8' --nist 'CM-7'
        --iso27001 'A.8.20' --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 2.3.3.8'
        --mscp 'system_settings_content_caching_disable')

    if [[ "$activated" == "0" || "$allowed" == "0" ]]; then
        add_audit_result --category 'Remote Access & Sharing Services' --control 'Content Caching' \
            --status PASS --severity Low --current "$current" "${fw[@]}" --recommendation 'No action required.'
    elif [[ "$activated" == "1" ]]; then
        add_audit_result --category 'Remote Access & Sharing Services' --control 'Content Caching' \
            --status FAIL --severity Low --current "$current" "${fw[@]}" \
            --recommendation 'Disable Content Caching in System Settings > General > Sharing, or deploy allowContentCaching=false.'
    else
        add_audit_result --category 'Remote Access & Sharing Services' --control 'Content Caching' \
            --status WARN --severity Low --current "$current - not enforced by a configuration profile" "${fw[@]}" \
            --recommendation 'Deploy a Restrictions profile with allowContentCaching=false.'
    fi
}

check_media_sharing_disabled() {
    local sharing modification
    sharing=$(managed_pref_read com.apple.applicationaccess allowMediaSharing)
    modification=$(managed_pref_read com.apple.applicationaccess allowMediaSharingModification)
    local current="allowMediaSharing=${sharing:-not set}, allowMediaSharingModification=${modification:-not set}"
    local -a fw
    fw=(--recommended 'allowMediaSharing=false, allowMediaSharingModification=false' --cis 'CIS 4.1, 4.8'
        --nist 'CM-7' --iso27001 'A.8.20' --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 2.3.3.9'
        --mscp 'system_settings_media_sharing_disabled')

    if [[ "$sharing" == "0" && "$modification" == "0" ]]; then
        add_audit_result --category 'Remote Access & Sharing Services' --control 'Media Sharing' \
            --status PASS --severity Low --current "$current" "${fw[@]}" --recommendation 'No action required.'
    elif [[ "$sharing" == "1" || "$modification" == "1" ]]; then
        add_audit_result --category 'Remote Access & Sharing Services' --control 'Media Sharing' \
            --status FAIL --severity Low --current "$current" "${fw[@]}" \
            --recommendation 'Deploy a Restrictions profile with allowMediaSharing=false and allowMediaSharingModification=false (turn Media Sharing off for each user first, or the profile locks it on).'
    else
        add_audit_result --category 'Remote Access & Sharing Services' --control 'Media Sharing' \
            --status WARN --severity Low --current "$current - not enforced by a configuration profile" "${fw[@]}" \
            --recommendation 'Deploy a Restrictions profile with allowMediaSharing=false and allowMediaSharingModification=false.'
    fi
}

check_bluetooth_sharing_disabled() {
    local -a fw
    fw=(--recommended 'PrefKeyServicesEnabled=0' --cis 'CIS 3.3, 4.1' --nist 'AC-18, CM-7'
        --mitre 'T1011.001 (Exfiltration Over Bluetooth)' --iso27001 'A.8.20' --nis2 'Art.21(2)(d)'
        --cis-macos 'CIS-macOS 2.3.3.10' --mscp 'system_settings_bluetooth_sharing_disable')

    if [[ -z "$CONSOLE_USER" ]]; then
        add_audit_result --category 'Remote Access & Sharing Services' --control 'Bluetooth Sharing' \
            --status WARN --severity Low --current 'No console user detected; per-user setting not readable' "${fw[@]}" \
            --recommendation 'Re-run while a user is logged in, or verify in System Settings > General > Sharing.'
        return 0
    fi

    run_as_user defaults -currentHost read com.apple.Bluetooth PrefKeyServicesEnabled
    if [[ $RUN_AS_USER_STATUS -eq 0 && "$RUN_AS_USER_OUTPUT" == "1" ]]; then
        add_audit_result --category 'Remote Access & Sharing Services' --control 'Bluetooth Sharing' \
            --status FAIL --severity Medium --current "Bluetooth Sharing enabled for $CONSOLE_USER" "${fw[@]}" \
            --recommendation 'Disable Bluetooth Sharing in System Settings > General > Sharing.'
    elif [[ $RUN_AS_USER_STATUS -eq 0 || "$RUN_AS_USER_OUTPUT" == *"does not exist"* || "$RUN_AS_USER_OUTPUT" == *"not found"* ]]; then
        # Key absent = never enabled (the default), same as an explicit 0.
        add_audit_result --category 'Remote Access & Sharing Services' --control 'Bluetooth Sharing' \
            --status PASS --severity Medium --current "Bluetooth Sharing disabled for $CONSOLE_USER" "${fw[@]}" \
            --recommendation 'No action required.'
    else
        add_audit_result --category 'Remote Access & Sharing Services' --control 'Bluetooth Sharing' \
            --status WARN --severity Low --current "Query failed: $RUN_AS_USER_OUTPUT" "${fw[@]}" \
            --recommendation 'Verify manually in System Settings > General > Sharing > Bluetooth Sharing.'
    fi
}

# ---- 19-ssh.zsh ----
#
# Domain 10: SSH Server & Client Hardening

check_sshd_password_auth() {
    write_section_banner 'SSH Server & Client Hardening - sshd Password Authentication'
    run_root sshd -T

    if [[ $ROOT_CMD_STATUS -ne 0 ]]; then
        add_audit_result --category 'SSH Server & Client Hardening' --control 'sshd Password Authentication' \
            --status WARN --severity Low --current 'sshd not available for query' \
            --recommended 'PasswordAuthentication no' \
            --cis 'CIS 5.9' --nist 'IA-2, IA-5' --cis-macos 'CIS-macOS 5.9' --mscp 'os_sshd_password_authentication_disable' \
            --recommendation 'Unable to query sshd effective configuration; verify manually with "sshd -T".'
        return
    fi

    local line value
    line=$(print -r -- "$ROOT_CMD_OUTPUT" | grep -i '^passwordauthentication' | head -1)
    value="${${line#* }:l}"

    case "$value" in
        no)
            add_audit_result --category 'SSH Server & Client Hardening' --control 'sshd Password Authentication' \
                --status PASS --severity High --current 'PasswordAuthentication no' \
                --recommended 'PasswordAuthentication no' \
                --cis 'CIS 5.9' --nist 'IA-2, IA-5' --mitre 'T1110 (Brute Force)' --iso27001 'A.8.5' \
                --nis2 'Art.21(2)(i)' --nsa 'NSA/CISA SSH Hardening Guidance' --cis-macos 'CIS-macOS 5.9' --mscp 'os_sshd_password_authentication_disable' \
                --recommendation 'No action required.'
            ;;
        yes)
            add_audit_result --category 'SSH Server & Client Hardening' --control 'sshd Password Authentication' \
                --status WARN --severity High --current 'PasswordAuthentication yes' \
                --recommended 'PasswordAuthentication no' \
                --cis 'CIS 5.9' --nist 'IA-2, IA-5' --mitre 'T1110 (Brute Force)' --iso27001 'A.8.5' \
                --nis2 'Art.21(2)(i)' --nsa 'NSA/CISA SSH Hardening Guidance' --cis-macos 'CIS-macOS 5.9' --mscp 'os_sshd_password_authentication_disable' \
                --recommendation 'Set "PasswordAuthentication no" in /etc/ssh/sshd_config and rely on key-based authentication.'
            ;;
        *)
            add_audit_result --category 'SSH Server & Client Hardening' --control 'sshd Password Authentication' \
                --status WARN --severity Low --current "Query failed or unrecognized output: $line" \
                --recommended 'PasswordAuthentication no' \
                --cis 'CIS 5.9' --nist 'IA-2, IA-5' --cis-macos 'CIS-macOS 5.9' --mscp 'os_sshd_password_authentication_disable' \
                --recommendation 'Unable to determine PasswordAuthentication setting; verify manually with "sshd -T".'
            ;;
    esac
}

check_sshd_permit_root_login() {
    run_root sshd -T

    if [[ $ROOT_CMD_STATUS -ne 0 ]]; then
        add_audit_result --category 'SSH Server & Client Hardening' --control 'sshd Permit Root Login' \
            --status WARN --severity Low --current 'sshd not available for query' \
            --recommended 'PermitRootLogin no' \
            --cis 'CIS 5.9' --nist 'AC-6, IA-2' --cis-macos 'CIS-macOS 5.9' --mscp 'os_sshd_permit_root_login_disable' \
            --recommendation 'Unable to query sshd effective configuration; verify manually with "sshd -T".'
        return
    fi

    local line value
    line=$(print -r -- "$ROOT_CMD_OUTPUT" | grep -i '^permitrootlogin' | head -1)
    value="${${line#* }:l}"

    if [[ "$value" == "no" ]]; then
        add_audit_result --category 'SSH Server & Client Hardening' --control 'sshd Permit Root Login' \
            --status PASS --severity High --current 'PermitRootLogin no' \
            --recommended 'PermitRootLogin no' \
            --cis 'CIS 5.9' --nist 'AC-6, IA-2' --mitre 'T1078.001 (Default Accounts)' --iso27001 'A.8.5' \
            --nis2 'Art.21(2)(i)' --cis-macos 'CIS-macOS 5.9' --mscp 'os_sshd_permit_root_login_disable' \
            --recommendation 'No action required.'
    else
        add_audit_result --category 'SSH Server & Client Hardening' --control 'sshd Permit Root Login' \
            --status FAIL --severity High --current "PermitRootLogin ${value:-unknown}" \
            --recommended 'PermitRootLogin no' \
            --cis 'CIS 5.9' --nist 'AC-6, IA-2' --mitre 'T1078.001 (Default Accounts)' --iso27001 'A.8.5' \
            --nis2 'Art.21(2)(i)' --cis-macos 'CIS-macOS 5.9' --mscp 'os_sshd_permit_root_login_disable' \
            --recommendation 'Set "PermitRootLogin no" in /etc/ssh/sshd_config.'
    fi
}

check_sshd_weak_ciphers() {
    run_root sshd -T

    if [[ $ROOT_CMD_STATUS -ne 0 ]]; then
        add_audit_result --category 'SSH Server & Client Hardening' --control 'sshd Weak Ciphers' \
            --status WARN --severity Low --current 'sshd not available for query' \
            --recommended 'No weak (3des-cbc/arcfour/*-cbc) ciphers configured' \
            --cis 'CIS 5.9' --nist 'SC-13' --cis-macos 'CIS-macOS 5.9' --mscp 'os_sshd_channel_timeout_configure' \
            --recommendation 'Unable to query sshd effective configuration; verify manually with "sshd -T".'
        return
    fi

    local line ciphers_lower
    line=$(print -r -- "$ROOT_CMD_OUTPUT" | grep -i '^ciphers' | head -1)

    if [[ -z "$line" ]]; then
        add_audit_result --category 'SSH Server & Client Hardening' --control 'sshd Weak Ciphers' \
            --status PASS --severity Medium --current 'No explicit Ciphers directive (Apple default ciphers apply)' \
            --recommended 'No weak (3des-cbc/arcfour/*-cbc) ciphers configured' \
            --cis 'CIS 5.9' --nist 'SC-13' --mitre 'T1040 (Network Sniffing)' --iso27001 'A.8.24' \
            --nis2 'Art.21(2)(h)' --cis-macos 'CIS-macOS 5.9' --mscp 'os_sshd_channel_timeout_configure' \
            --recommendation 'No action required.'
        return
    fi

    ciphers_lower="${line:l}"
    if [[ "$ciphers_lower" == *"3des-cbc"* || "$ciphers_lower" == *"arcfour"* || "$ciphers_lower" == *"-cbc"* ]]; then
        add_audit_result --category 'SSH Server & Client Hardening' --control 'sshd Weak Ciphers' \
            --status WARN --severity Medium --current "$line" \
            --recommended 'No weak (3des-cbc/arcfour/*-cbc) ciphers configured' \
            --cis 'CIS 5.9' --nist 'SC-13' --mitre 'T1040 (Network Sniffing)' --iso27001 'A.8.24' \
            --nis2 'Art.21(2)(h)' --cis-macos 'CIS-macOS 5.9' --mscp 'os_sshd_channel_timeout_configure' \
            --recommendation 'Restrict to AES-GCM/ChaCha20 AEAD ciphers via "Ciphers" in /etc/ssh/sshd_config.'
    else
        add_audit_result --category 'SSH Server & Client Hardening' --control 'sshd Weak Ciphers' \
            --status PASS --severity Medium --current "$line" \
            --recommended 'No weak (3des-cbc/arcfour/*-cbc) ciphers configured' \
            --cis 'CIS 5.9' --nist 'SC-13' --mitre 'T1040 (Network Sniffing)' --iso27001 'A.8.24' \
            --nis2 'Art.21(2)(h)' --cis-macos 'CIS-macOS 5.9' --mscp 'os_sshd_channel_timeout_configure' \
            --recommendation 'No action required.'
    fi
}

check_ssh_client_strict_host_key_checking() {
    if [[ -z "$CONSOLE_USER" ]]; then
        add_audit_result --category 'SSH Server & Client Hardening' --control 'SSH Client Strict Host Key Checking' \
            --status WARN --severity Low --current 'No console user detected' \
            --recommended 'N/A' --cis-macos 'CIS-macOS 5.9' --mscp 'N/A' \
            --recommendation 'Re-run interactively at a console login session to evaluate the SSH client configuration.'
        return
    fi

    local config_path
    config_path="$(eval echo ~$CONSOLE_USER)/.ssh/config"
    run_as_user cat "$config_path"

    # A missing ~/.ssh/config is a normal, common case, not an error.
    if [[ $RUN_AS_USER_STATUS -ne 0 || -z "$RUN_AS_USER_OUTPUT" ]]; then
        add_audit_result --category 'SSH Server & Client Hardening' --control 'SSH Client Strict Host Key Checking' \
            --status INFO --severity Informational --current 'No ~/.ssh/config present' \
            --recommended 'N/A' --cis-macos 'CIS-macOS 5.9' --mscp 'N/A' \
            --recommendation 'Informational only. No client-side SSH config overrides are in effect.'
        return
    fi

    if print -r -- "$RUN_AS_USER_OUTPUT" | grep -Eqi 'StrictHostKeyChecking[[:space:]]+no'; then
        add_audit_result --category 'SSH Server & Client Hardening' --control 'SSH Client Strict Host Key Checking' \
            --status WARN --severity Low --current 'StrictHostKeyChecking no found in ~/.ssh/config' \
            --recommended 'StrictHostKeyChecking not overridden to "no"' \
            --cis 'CIS 5.9' --nist 'SC-8' --mitre 'T1557 (Adversary-in-the-Middle)' --iso27001 'A.8.24' \
            --nis2 'Art.21(2)(h)' --cis-macos 'CIS-macOS 5.9' --mscp 'N/A' \
            --recommendation 'Remove or correct that override — it disables protection against host-key-spoofing MITM attacks.'
    else
        add_audit_result --category 'SSH Server & Client Hardening' --control 'SSH Client Strict Host Key Checking' \
            --status PASS --severity Low --current 'No StrictHostKeyChecking override found' \
            --recommended 'StrictHostKeyChecking not overridden to "no"' \
            --cis 'CIS 5.9' --nist 'SC-8' --mitre 'T1557 (Adversary-in-the-Middle)' --iso27001 'A.8.24' \
            --nis2 'Art.21(2)(h)' --cis-macos 'CIS-macOS 5.9' --mscp 'N/A' \
            --recommendation 'No action required.'
    fi
}

# ---- 20-crypto-certs.zsh ----
#
# Domain 11: Cryptography & Certificate Trust

check_system_trust_settings_overrides() {
    write_section_banner 'Cryptography & Certificate Trust - System Trust Settings Overrides'
    run_root security dump-trust-settings -d

    if [[ $ROOT_CMD_STATUS -ne 0 || "${ROOT_CMD_OUTPUT:l}" == *"no trust settings"* || "${ROOT_CMD_OUTPUT:l}" == *"no admin trust settings"* ]]; then
        add_audit_result --category 'Cryptography & Certificate Trust' --control 'System Trust Settings Overrides' \
            --status PASS --severity Medium --current 'No admin-level trust setting overrides' \
            --recommended 'No admin-level trust setting overrides' \
            --cis 'CIS 3.10' --nist 'SC-17' --mitre 'T1553.004 (Install Root Certificate)' --iso27001 'A.8.24' \
            --nis2 'Art.21(2)(h)' --nsa 'NSA/CISA PKI Guidance' --cis-macos 'CIS-macOS 5.4' --mscp 'N/A' \
            --recommendation 'No action required.'
        return
    fi

    local count
    count=$(print -r -- "$ROOT_CMD_OUTPUT" | grep -c '^[[:space:]]*[0-9]\+\.')

    add_audit_result --category 'Cryptography & Certificate Trust' --control 'System Trust Settings Overrides' \
        --status WARN --severity Medium --current "$count admin-level trust setting override(s) found" \
        --recommended 'No admin-level trust setting overrides' \
        --cis 'CIS 3.10' --nist 'SC-17' --mitre 'T1553.004 (Install Root Certificate)' --iso27001 'A.8.24' \
        --nis2 'Art.21(2)(h)' --nsa 'NSA/CISA PKI Guidance' --cis-macos 'CIS-macOS 5.4' --mscp 'N/A' \
        --recommendation 'Review each overridden root/intermediate CA trust setting — an unexpected trusted root is a MITM risk.'
}

check_login_keychain_lock_on_sleep() {
    if [[ -z "$CONSOLE_USER" ]]; then
        add_audit_result --category 'Cryptography & Certificate Trust' --control 'Login Keychain Lock on Sleep' \
            --status WARN --severity Low --current 'No console user detected' \
            --recommended 'N/A' --cis-macos 'CIS-macOS 5.4' --mscp 'N/A' \
            --recommendation 'Re-run interactively at a console login session to evaluate the login keychain settings.'
        return
    fi

    local keychain_path
    keychain_path="$(eval echo ~$CONSOLE_USER)/Library/Keychains/login.keychain-db"
    run_as_user security show-keychain-info "$keychain_path"

    if [[ $RUN_AS_USER_STATUS -ne 0 ]]; then
        # Fault isolation: a failing query must never be reported
        # identically to a verified "flag missing" WARN below.
        add_audit_result --category 'Cryptography & Certificate Trust' --control 'Login Keychain Lock on Sleep' \
            --status WARN --severity Low --current "Unable to query keychain settings: $RUN_AS_USER_OUTPUT" \
            --recommended 'N/A' --cis-macos 'CIS-macOS 5.4' --mscp 'N/A' \
            --recommendation 'Unable to determine login keychain settings; verify manually with "security show-keychain-info".'
        return
    fi

    if [[ "$RUN_AS_USER_OUTPUT" == *"lock-on-sleep"* ]]; then
        add_audit_result --category 'Cryptography & Certificate Trust' --control 'Login Keychain Lock on Sleep' \
            --status PASS --severity Medium --current "$RUN_AS_USER_OUTPUT" \
            --recommended 'lock-on-sleep enabled' \
            --cis 'CIS 3.10' --nist 'SC-28' --iso27001 'A.8.24' --nis2 'Art.21(2)(h)' --cis-macos 'CIS-macOS 5.4' --mscp 'N/A' \
            --recommendation 'No action required.'
    else
        add_audit_result --category 'Cryptography & Certificate Trust' --control 'Login Keychain Lock on Sleep' \
            --status WARN --severity Medium --current "$RUN_AS_USER_OUTPUT" \
            --recommended 'lock-on-sleep enabled' \
            --cis 'CIS 3.10' --nist 'SC-28' --iso27001 'A.8.24' --nis2 'Art.21(2)(h)' --cis-macos 'CIS-macOS 5.4' --mscp 'N/A' \
            --recommendation 'Enable "Lock keychain when sleeping" via Keychain Access > login keychain > Edit menu > Change Settings, or "security set-keychain-settings -l login.keychain-db".'
    fi
}

check_fips_validated_crypto_note() {
    # No command: always INFO. Mirrors the honesty-over-false-precision
    # pattern the original Windows tool used for CPU-mitigation-bitmask
    # checks it couldn't cleanly assert.
    add_audit_result --category 'Cryptography & Certificate Trust' --control 'FIPS-Validated Cryptography' \
        --status INFO --severity Informational \
        --current "Apple's corecrypto module holds FIPS 140-3 validation on supported macOS releases" \
        --recommended 'N/A' --cis-macos 'CIS-macOS 5.4' --mscp 'N/A' \
        --recommendation 'Informational only. If FIPS mode is a compliance requirement, confirm the specific validation certificate covers the OS build in use via Apple'"'"'s published FIPS compliance documentation.'
}

# ---- 21-audit-logging.zsh ----
#
# Domain 12: Audit, Logging & Telemetry

check_audit_subsystem_enabled() {
    write_section_banner 'Audit, Logging & Telemetry - Audit Subsystem Enabled'
    run_root launchctl list com.apple.auditd

    if [[ $ROOT_CMD_STATUS -eq 0 ]]; then
        add_audit_result --category 'Audit, Logging & Telemetry' --control 'Audit Subsystem Enabled' \
            --status PASS --severity Medium --current 'auditd is running' \
            --recommended 'auditd is running' \
            --cis 'CIS 8.1' --nist 'AU-2, AU-12' --mitre 'T1562.008 (Disable Cloud Logs)' --iso27001 'A.8.15' \
            --nis2 'Art.21(2)(f)' --nsa 'NSA/CISA Logging Guidance' --cis-macos 'CIS-macOS 3.1' --mscp 'os_auditd_enabled' \
            --recommendation 'No action required.'
    else
        add_audit_result --category 'Audit, Logging & Telemetry' --control 'Audit Subsystem Enabled' \
            --status FAIL --severity Medium --current 'auditd is not running' \
            --recommended 'auditd is running' \
            --cis 'CIS 8.1' --nist 'AU-2, AU-12' --mitre 'T1562.008 (Disable Cloud Logs)' --iso27001 'A.8.15' \
            --nis2 'Art.21(2)(f)' --nsa 'NSA/CISA Logging Guidance' --cis-macos 'CIS-macOS 3.1' --mscp 'os_auditd_enabled' \
            --recommendation 'Investigate why the built-in BSM audit daemon isn'"'"'t running; it should start automatically at boot — "sudo launchctl bootstrap system /System/Library/LaunchDaemons/com.apple.auditd.plist".'
    fi
}

# Reads the "flags:" line from an audit_control file. Parameterized so
# it's directly testable against a scratch file, same as Task 6.
_audit_control_flags_check() {
    local ac_path="$1"

    if [[ ! -f "$ac_path" ]]; then
        add_audit_result --category 'Audit, Logging & Telemetry' --control 'Audit Control Flags' \
            --status WARN --severity Medium --current 'audit_control not found' \
            --recommended 'flags line includes the aa class' \
            --cis 'CIS 8.1' --nist 'AU-2' --mitre 'T1078' --iso27001 'A.8.15' \
            --nis2 'Art.21(2)(f)' --cis-macos 'CIS-macOS 3.1' --mscp 'os_audit_control_configure' \
            --recommendation 'Restore /etc/security/audit_control from a known-good source.'
        return
    fi

    local flags_line flags_value
    flags_line=$(grep '^flags:' "$ac_path" | head -1)
    flags_value="${flags_line#flags:}"

    local -a classes
    classes=(${(s:,:)flags_value})

    local has_aa=0 c
    for c in "${classes[@]}"; do
        [[ "${c:l}" == "aa" ]] && has_aa=1
    done

    if (( has_aa )); then
        add_audit_result --category 'Audit, Logging & Telemetry' --control 'Audit Control Flags' \
            --status PASS --severity Medium --current "$flags_line" \
            --recommended 'flags line includes the aa class' \
            --cis 'CIS 8.1' --nist 'AU-2' --mitre 'T1078' --iso27001 'A.8.15' \
            --nis2 'Art.21(2)(f)' --cis-macos 'CIS-macOS 3.1' --mscp 'os_audit_control_configure' \
            --recommendation 'No action required.'
    else
        add_audit_result --category 'Audit, Logging & Telemetry' --control 'Audit Control Flags' \
            --status WARN --severity Medium --current "${flags_line:-No flags line found in $ac_path}" \
            --recommended 'flags line includes the aa class' \
            --cis 'CIS 8.1' --nist 'AU-2' --mitre 'T1078' --iso27001 'A.8.15' \
            --nis2 'Art.21(2)(f)' --cis-macos 'CIS-macOS 3.1' --mscp 'os_audit_control_configure' \
            --recommendation 'Add the aa class to /etc/security/audit_control flags for authentication-event coverage.'
    fi
}

check_audit_control_flags() {
    _audit_control_flags_check '/etc/security/audit_control'
}

# Reads AutoSubmit from a scratch or real DiagnosticMessagesHistory.plist.
# Real-world constraint (confirmed live against the actual system plist,
# not theoretical): AutoSubmit is a genuine plist Boolean, so PlistBuddy
# prints "true"/"false" — never the literal string "1"/"0" — so this must
# not compare only against "1".
_diagnostics_autosubmit_check() {
    local plist_path="$1"
    local autosubmit
    autosubmit=$(plist_value_safe "$plist_path" 'AutoSubmit' '0')

    if [[ "${autosubmit:l}" == "1" || "${autosubmit:l}" == "true" ]]; then
        add_audit_result --category 'Audit, Logging & Telemetry' --control 'Diagnostics Auto-Submit' \
            --status WARN --severity Low --current 'AutoSubmit=1 (diagnostic data sent to Apple)' \
            --recommended 'AutoSubmit=0' \
            --cis 'CIS 8.11' --nist 'SI-4' --iso27001 'A.8.16' --nis2 'Art.21(2)(f)' --cis-macos 'CIS-macOS 3.4' --mscp 'os_diagnostics_reports_disable' \
            --recommendation 'Disable in System Settings > Privacy & Security > Analytics & Improvements if sending device diagnostics off-network is against policy.'
    else
        add_audit_result --category 'Audit, Logging & Telemetry' --control 'Diagnostics Auto-Submit' \
            --status PASS --severity Low --current "AutoSubmit=$autosubmit" \
            --recommended 'AutoSubmit=0' \
            --cis 'CIS 8.11' --nist 'SI-4' --iso27001 'A.8.16' --nis2 'Art.21(2)(f)' --cis-macos 'CIS-macOS 3.4' --mscp 'os_diagnostics_reports_disable' \
            --recommendation 'No action required.'
    fi
}

check_diagnostics_autosubmit() {
    _diagnostics_autosubmit_check '/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist'
}

: ${LOG_BIN:=/usr/bin/log}

check_unified_log_security_events() {
    # Bounded to a short recent window (15 minutes), matching the
    # original tool's performance-bounded-scans principle — verified
    # live that this query returns in well under a second. This is
    # coarse activity telemetry across three security-relevant
    # subsystems (sudo invocations, TCC activity, Gatekeeper/syspolicyd
    # activity), not incident detection: distinguishing "denied" from
    # "allowed" would require guessing at exact log message wording this
    # project has no way to verify without deliberately triggering a
    # failure on a real system, which is out of scope for an audit tool
    # — per honesty-over-false-precision, this reports a count only.
    #
    # $LOG_BIN, not a bare "log": zsh has its own unrelated builtin named
    # "log" (confirmed live: `type log` reports "shell builtin"), so a
    # bare call always hits that instead of Apple's /usr/bin/log and
    # fails with "too many arguments" — the same absolute-path-variable
    # workaround Task 13 used for socketfilterfw, so tests can still
    # override it to a bare stub name.
    run_root "$LOG_BIN" show --style syslog --predicate 'process == "sudo" OR subsystem == "com.apple.TCC" OR process == "syspolicyd"' --last 15m

    if [[ $ROOT_CMD_STATUS -ne 0 ]]; then
        add_audit_result --category 'Audit, Logging & Telemetry' --control 'Unified Log Security-Relevant Activity' \
            --status WARN --severity Low --current "log query failed: $ROOT_CMD_OUTPUT" \
            --recommended 'N/A' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'Unable to query the unified log; verify manually with "log show --predicate ... --last 15m".'
        return
    fi

    local count
    count=$(print -r -- "$ROOT_CMD_OUTPUT" | grep -vc '^Timestamp')

    add_audit_result --category 'Audit, Logging & Telemetry' --control 'Unified Log Security-Relevant Activity' \
        --status INFO --severity Informational \
        --current "$count security-relevant log event(s) in the last 15 minutes (sudo/TCC/Gatekeeper activity — coarse telemetry, not incident detection)" \
        --recommended 'N/A' --cis 'CIS 8.2' --nist 'AU-6' --iso27001 'A.8.15' --nis2 'Art.21(2)(f)' --cis-macos 'N/A' --mscp 'N/A' \
        --recommendation 'Informational only. For incident investigation, query the unified log directly with a predicate targeted at the timeframe and subsystem of interest.'
}

# --- CIS Apple macOS 26 Tahoe v1.0.0 sections 2.3.2.x and 3.3-3.5 ---

check_network_time_enabled() {
    run_root systemsetup -getusingnetworktime
    local -a fw
    fw=(--recommended 'Network Time: On' --cis 'CIS 8.4' --nist 'AU-8' --mitre 'T1070.006 (Timestomp)'
        --iso27001 'A.8.17' --nis2 'Art.21(2)(f)' --cis-macos 'CIS-macOS 2.3.2.1' --mscp 'system_settings_time_server_enforce')

    if [[ "$ROOT_CMD_OUTPUT" == *"Network Time: On"* ]]; then
        add_audit_result --category 'Audit, Logging & Telemetry' --control 'Set Time and Date Automatically' \
            --status PASS --severity Medium --current 'Network Time: On' "${fw[@]}" --recommendation 'No action required.'
    elif [[ "$ROOT_CMD_OUTPUT" == *"Network Time: Off"* ]]; then
        add_audit_result --category 'Audit, Logging & Telemetry' --control 'Set Time and Date Automatically' \
            --status FAIL --severity Medium --current 'Network Time: Off' "${fw[@]}" \
            --recommendation 'Enable network time so log timestamps stay correlatable: "sudo systemsetup -setusingnetworktime on".'
    else
        add_audit_result --category 'Audit, Logging & Telemetry' --control 'Set Time and Date Automatically' \
            --status WARN --severity Low --current "Query failed or unrecognized output: $ROOT_CMD_OUTPUT" "${fw[@]}" \
            --recommendation 'Verify manually in System Settings > General > Date & Time.'
    fi
}

check_time_service_running() {
    run_root launchctl list
    local -a fw
    fw=(--recommended 'com.apple.timed loaded' --cis 'CIS 8.4' --nist 'AU-8' --iso27001 'A.8.17'
        --nis2 'Art.21(2)(f)' --cis-macos 'CIS-macOS 2.3.2.2' --mscp 'os_time_server_enabled')

    if [[ $ROOT_CMD_STATUS -ne 0 ]]; then
        add_audit_result --category 'Audit, Logging & Telemetry' --control 'Time Service (timed) Running' \
            --status WARN --severity Low --current "launchctl query failed: $ROOT_CMD_OUTPUT" "${fw[@]}" \
            --recommendation 'Verify manually with "sudo launchctl list | grep com.apple.timed".'
    elif [[ "$ROOT_CMD_OUTPUT" == *"com.apple.timed"* ]]; then
        add_audit_result --category 'Audit, Logging & Telemetry' --control 'Time Service (timed) Running' \
            --status PASS --severity Medium --current 'com.apple.timed is loaded' "${fw[@]}" --recommendation 'No action required.'
    else
        add_audit_result --category 'Audit, Logging & Telemetry' --control 'Time Service (timed) Running' \
            --status FAIL --severity Medium --current 'com.apple.timed is not loaded' "${fw[@]}" \
            --recommendation 'Re-enable the time daemon: "sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.timed.plist".'
    fi
}

_install_log_retention_check() {
    local asl_path="$1"
    local -a fw
    fw=(--recommended 'ttl >= 365 and no all_max limit' --cis 'CIS 8.1, 8.3' --nist 'AU-4, AU-11'
        --mitre 'T1070 (Indicator Removal)' --iso27001 'A.8.15' --nis2 'Art.21(2)(f)'
        --cis-macos 'CIS-macOS 3.3' --mscp 'os_install_log_retention_configure')

    if [[ ! -f "$asl_path" ]]; then
        add_audit_result --category 'Audit, Logging & Telemetry' --control 'install.log Retention' \
            --status WARN --severity Low --current "$asl_path not found" "${fw[@]}" \
            --recommendation 'Restore /etc/asl/com.apple.install from a known-good source.'
        return 0
    fi

    local content ttl
    content=$(< "$asl_path")
    ttl=$(print -r -- "$content" | grep -oiE 'ttl=[0-9]+' | head -1 | cut -d= -f2)
    local current="ttl=${ttl:-not set}$( [[ "$content" == *all_max=* ]] && print -r -- ', all_max limit present')"

    if [[ "$ttl" == <-> ]] && (( ttl >= 365 )) && [[ "$content" != *all_max=* ]]; then
        add_audit_result --category 'Audit, Logging & Telemetry' --control 'install.log Retention' \
            --status PASS --severity Low --current "$current" "${fw[@]}" --recommendation 'No action required.'
    else
        add_audit_result --category 'Audit, Logging & Telemetry' --control 'install.log Retention' \
            --status FAIL --severity Low --current "$current" "${fw[@]}" \
            --recommendation 'In /etc/asl/com.apple.install, add ttl=365 to the install.log line and remove any all_max= size cap.'
    fi
}

check_install_log_retention() {
    _install_log_retention_check /etc/asl/com.apple.install
}

# Converts an audit_control expire-after token ("60d", "5G", "1y") to
# days (unit d/h/s/y) or gigabytes (unit B/K/M/G). Prints "<kind> <n>".
_expire_after_token() {
    local tok="$1" n unit
    n="${tok%%[A-Za-z]*}"; unit="${tok#$n}"
    [[ "$n" == <-> ]] || return 1
    case "$unit" in
        d|D) print -r -- "days $n" ;;
        y|Y) print -r -- "days $(( n * 365 ))" ;;
        h|H) print -r -- "days $(( n / 24 ))" ;;
        s|S) print -r -- "days $(( n / 86400 ))" ;;
        G|g) print -r -- "gb $n" ;;
        M|m) print -r -- "gb $(( n / 1024 ))" ;;
        K|k|B|b|'') print -r -- "gb 0" ;;
        *) return 1 ;;
    esac
}

_audit_retention_check() {
    local ac_path="$1"
    local -a fw
    fw=(--recommended 'expire-after >= 60d OR >= 5G' --cis 'CIS 8.1, 8.3' --nist 'AU-4, AU-11'
        --mitre 'T1070 (Indicator Removal)' --iso27001 'A.8.15' --nis2 'Art.21(2)(f)'
        --cis-macos 'CIS-macOS 3.4' --mscp 'audit_retention_configure')

    if [[ ! -f "$ac_path" ]]; then
        add_audit_result --category 'Audit, Logging & Telemetry' --control 'Security Auditing Retention' \
            --status WARN --severity Medium --current 'audit_control not found (BSM auditing not configured)' "${fw[@]}" \
            --recommendation 'Configure BSM auditing (/etc/security/audit_control) with expire-after:60d OR 5G, or document the alternative log pipeline.'
        return 0
    fi

    local line value tok parsed ok=0
    line=$(grep '^expire-after:' "$ac_path" | head -1)
    value="${line#expire-after:}"
    for tok in ${(s: :)${value//[^0-9A-Za-z ]/ }}; do
        parsed=$(_expire_after_token "$tok") || continue
        case "$parsed" in
            days\ *) (( ${parsed#days } >= 60 )) && ok=1 ;;
            gb\ *) (( ${parsed#gb } >= 5 )) && ok=1 ;;
        esac
    done

    if [[ $ok -eq 1 ]]; then
        add_audit_result --category 'Audit, Logging & Telemetry' --control 'Security Auditing Retention' \
            --status PASS --severity Medium --current "expire-after:$value" "${fw[@]}" --recommendation 'No action required.'
    else
        add_audit_result --category 'Audit, Logging & Telemetry' --control 'Security Auditing Retention' \
            --status FAIL --severity Medium --current "${line:-No expire-after line}" "${fw[@]}" \
            --recommendation 'Set "expire-after:60d OR 5G" in /etc/security/audit_control, then "sudo audit -s".'
    fi
}

check_audit_retention() {
    _audit_retention_check /etc/security/audit_control
}

# "uid gid permissions" for one path; separate so tests can stub it
# (scratch files can't be made root-owned without privileges).
_file_owner_mode() {
    stat -f '%u %g %Sp' "$1" 2>/dev/null
}

_audit_records_access_check() {
    local ac_path="$1"
    local -a fw
    fw=(--recommended 'audit_control and audit trail files owned root:wheel, mode -r--r-----' --cis 'CIS 3.3'
        --nist 'AU-9' --mitre 'T1070.002 (Clear Linux or Mac System Logs)' --iso27001 'A.8.15'
        --nis2 'Art.21(2)(f)' --cis-macos 'CIS-macOS 3.5'
        --mscp 'audit_control_owner_configure, audit_control_group_configure, audit_control_mode_configure, audit_files_owner_configure, audit_files_group_configure, audit_files_mode_configure')

    if [[ ! -f "$ac_path" ]]; then
        add_audit_result --category 'Audit, Logging & Telemetry' --control 'Access to Audit Records Controlled' \
            --status WARN --severity Medium --current 'audit_control not found (BSM auditing not configured)' "${fw[@]}" \
            --recommendation 'Configure BSM auditing before audit-record permissions can be assessed.'
        return 0
    fi

    local audit_dir
    audit_dir=$(grep '^dir:' "$ac_path" | head -1 | cut -d: -f2)
    local -a targets bad
    targets=("$ac_path")
    [[ -n "$audit_dir" && -d "$audit_dir" ]] && targets+=("$audit_dir"/*(N))

    local f info
    for f in "${targets[@]}"; do
        # "current" is a symlink to the active trail; CIS excludes it.
        [[ "${f:t}" == current ]] && continue
        info=$(_file_owner_mode "$f")
        [[ "$info" == "0 0 -r--r-----" ]] || bad+=("$f ($info)")
    done

    if [[ ${#bad[@]} -eq 0 ]]; then
        add_audit_result --category 'Audit, Logging & Telemetry' --control 'Access to Audit Records Controlled' \
            --status PASS --severity Medium --current "${#targets[@]} audit file(s) correctly owned and read-only" "${fw[@]}" \
            --recommendation 'No action required.'
    else
        add_audit_result --category 'Audit, Logging & Telemetry' --control 'Access to Audit Records Controlled' \
            --status FAIL --severity Medium --current "${#bad[@]} audit file(s) with incorrect owner, group or mode" \
            --details "${(F)bad}" "${fw[@]}" \
            --recommendation "Fix ownership and mode: sudo chown -R root:wheel $ac_path ${audit_dir:-/var/audit} && sudo chmod 0440 $ac_path && sudo chmod -R o-rw,g-w ${audit_dir:-/var/audit}"
    fi
}

check_audit_records_access() {
    _audit_records_access_check /etc/security/audit_control
}

# ---- 22-software-update.zsh ----
#
# Domain 13: Software Update & Patch Compliance
#
# Stays fully offline: only "softwareupdate --history" (local record) and
# "defaults read" are used — never "softwareupdate -l", which performs a
# live network scan against Apple's servers.

check_recent_update_history() {
    write_section_banner 'Software Update & Patch Compliance - Recent Update History'
    run_root softwareupdate --history

    # Real "softwareupdate --history" output (confirmed live): a header
    # line, a dashes separator line, then one data row per update in
    # chronological order (oldest first), each with a date column
    # formatted "YYYY-MM-DD, HH:MM:SS" — the date token itself carries a
    # trailing comma, split from the time as a separate whitespace token.
    local last_line
    last_line=$(print -r -- "$ROOT_CMD_OUTPUT" | grep -vE '^(Display Name|-+[[:space:]]*-+)' | grep -v '^[[:space:]]*$' | tail -1)

    local -a tokens
    tokens=(${(z)last_line})
    local token date_token=""
    for token in "${tokens[@]}"; do
        if [[ "$token" =~ '^[0-9]{4}-[0-9]{2}-[0-9]{2},?$' ]]; then
            date_token="${token%,}"
            break
        fi
    done

    local epoch=""
    if [[ -n "$date_token" ]]; then
        epoch=$(date -j -f "%Y-%m-%d" "$date_token" +%s 2>/dev/null)
    fi

    if [[ -z "$epoch" ]]; then
        add_audit_result --category 'Software Update & Patch Compliance' --control 'Recent Update History' \
            --status WARN --severity Medium \
            --current 'Unable to determine last update date from local history — offline check only, does not query Apple servers' \
            --recommended 'Last update within 45 days' \
            --cis 'CIS 7.3' --nist 'SI-2' --cis-macos 'CIS-macOS 1.1' --mscp 'os_software_update_enforce' \
            --recommendation 'Unable to parse local update history; verify manually with "softwareupdate --history".'
        return
    fi

    local now days_since
    now=$(date +%s)
    days_since=$(( (now - epoch) / 86400 ))

    if (( days_since <= 45 )); then
        add_audit_result --category 'Software Update & Patch Compliance' --control 'Recent Update History' \
            --status PASS --severity Medium --current "Last update: $date_token ($days_since day(s) ago)" \
            --recommended 'Last update within 45 days' \
            --cis 'CIS 7.3' --nist 'SI-2' --mitre 'T1210 (Exploitation of Remote Services)' --iso27001 'A.8.8' \
            --nis2 'Art.21(2)(e)' --nsa 'NSA/CISA Patch Management Guidance' --cis-macos 'CIS-macOS 1.1' --mscp 'os_software_update_enforce' \
            --recommendation 'No action required.'
    else
        add_audit_result --category 'Software Update & Patch Compliance' --control 'Recent Update History' \
            --status WARN --severity Medium --current "Last update: $date_token ($days_since day(s) ago)" \
            --recommended 'Last update within 45 days' \
            --cis 'CIS 7.3' --nist 'SI-2' --mitre 'T1210 (Exploitation of Remote Services)' --iso27001 'A.8.8' \
            --nis2 'Art.21(2)(e)' --nsa 'NSA/CISA Patch Management Guidance' --cis-macos 'CIS-macOS 1.1' --mscp 'os_software_update_enforce' \
            --recommendation 'Install pending updates via System Settings > General > Software Update.'
    fi
}

check_auto_update_configuration() {
    # CIS 1.2 (automatic check + download). Read through NSUserDefaults so
    # MDM-enforced values count; CriticalUpdateInstall is owned by
    # check_security_responses_install_enabled (CIS 1.5) so the same key
    # is never scored twice. Unset keys read as "0", matching the GUI
    # default of these settings being off until chosen during setup.
    local auto_check auto_download
    auto_check=$(managed_pref_read com.apple.SoftwareUpdate AutomaticCheckEnabled) || auto_check=0
    auto_download=$(managed_pref_read com.apple.SoftwareUpdate AutomaticDownload) || auto_download=0

    local current="AutomaticCheckEnabled=$auto_check, AutomaticDownload=$auto_download"

    if [[ "$auto_check" == "1" && "$auto_download" == "1" ]]; then
        add_audit_result --category 'Software Update & Patch Compliance' --control 'Automatic Update Configuration' \
            --status PASS --severity Medium --current "$current" \
            --recommended 'AutomaticCheckEnabled=1, AutomaticDownload=1' \
            --cis 'CIS 7.3, 7.4' --nist 'SI-2' --iso27001 'A.8.8' --nis2 'Art.21(2)(e)' --cis-macos 'CIS-macOS 1.2' --mscp 'system_settings_download_software_update_enforce' \
            --recommendation 'No action required.'
    else
        add_audit_result --category 'Software Update & Patch Compliance' --control 'Automatic Update Configuration' \
            --status WARN --severity Medium --current "$current" \
            --recommended 'AutomaticCheckEnabled=1, AutomaticDownload=1' \
            --cis 'CIS 7.3, 7.4' --nist 'SI-2' --iso27001 'A.8.8' --nis2 'Art.21(2)(e)' --cis-macos 'CIS-macOS 1.2' --mscp 'system_settings_download_software_update_enforce' \
            --recommendation 'Enable "Check for updates" and "Download new updates when available" in System Settings > General > Software Update > Automatic Updates.'
    fi
}

check_macos_updates_auto_install() {
    evaluate_managed_pref --category 'Software Update & Patch Compliance' --control 'Install macOS Updates Automatically' \
        --severity Medium --suite com.apple.SoftwareUpdate --key AutomaticallyInstallMacOSUpdates --expect 1 \
        --cis 'CIS 7.3, 7.4' --nist 'SI-2' --mitre 'T1210 (Exploitation of Remote Services)' --iso27001 'A.8.8' \
        --nis2 'Art.21(2)(e)' --cis-macos 'CIS-macOS 1.3' --mscp 'system_settings_install_macos_updates_enforce' \
        --recommendation 'Enable "Install macOS updates" in System Settings > General > Software Update > Automatic Updates, or enforce AutomaticallyInstallMacOSUpdates via profile. (CIS: if enabled during Setup Assistant, toggle it off and on to leave an auditable value.)'
}

check_app_store_updates_auto_install() {
    local commerce su
    commerce=$(managed_pref_read com.apple.commerce AutoUpdate)
    su=$(managed_pref_read com.apple.SoftwareUpdate AutomaticallyInstallAppUpdates)
    local current="com.apple.commerce AutoUpdate=${commerce:-not set}, AutomaticallyInstallAppUpdates=${su:-not set}"
    local -a fw
    fw=(--recommended 'AutoUpdate=1 or AutomaticallyInstallAppUpdates=1' --cis 'CIS 7.3, 7.4' --nist 'SI-2'
        --iso27001 'A.8.8' --nis2 'Art.21(2)(e)' --cis-macos 'CIS-macOS 1.4' --mscp 'os_software_update_app_update_enforce')

    if [[ "$commerce" == "1" || "$su" == "1" ]]; then
        add_audit_result --category 'Software Update & Patch Compliance' --control 'Install App Store Updates Automatically' \
            --status PASS --severity Low --current "$current" "${fw[@]}" --recommendation 'No action required.'
    elif [[ "$commerce" == "0" || "$su" == "0" ]]; then
        add_audit_result --category 'Software Update & Patch Compliance' --control 'Install App Store Updates Automatically' \
            --status FAIL --severity Low --current "$current" "${fw[@]}" \
            --recommendation 'Enable "Install application updates from the App Store" in System Settings > General > Software Update > Automatic Updates.'
    else
        add_audit_result --category 'Software Update & Patch Compliance' --control 'Install App Store Updates Automatically' \
            --status WARN --severity Low --current "$current" "${fw[@]}" \
            --recommendation 'Enable "Install application updates from the App Store", or enforce AutomaticallyInstallAppUpdates via profile.'
    fi
}

check_security_responses_install_enabled() {
    local config_data critical
    config_data=$(managed_pref_read com.apple.SoftwareUpdate ConfigDataInstall)
    critical=$(managed_pref_read com.apple.SoftwareUpdate CriticalUpdateInstall)
    local current="ConfigDataInstall=${config_data:-not set}, CriticalUpdateInstall=${critical:-not set}"
    local -a fw
    fw=(--recommended 'ConfigDataInstall=1, CriticalUpdateInstall=1' --cis 'CIS 7.3, 7.4, 7.7' --nist 'SI-2, SI-3'
        --mitre 'T1204.002 (Malicious File)' --iso27001 'A.8.8' --nis2 'Art.21(2)(e)'
        --cis-macos 'CIS-macOS 1.5' --mscp 'system_settings_critical_update_install_enforce')

    if [[ "$config_data" == "1" && "$critical" == "1" ]]; then
        add_audit_result --category 'Software Update & Patch Compliance' --control 'Install Security Responses & System Files' \
            --status PASS --severity High --current "$current" "${fw[@]}" --recommendation 'No action required.'
    elif [[ "$config_data" == "0" || "$critical" == "0" ]]; then
        add_audit_result --category 'Software Update & Patch Compliance' --control 'Install Security Responses & System Files' \
            --status FAIL --severity High --current "$current" "${fw[@]}" \
            --recommendation 'Enable "Install Security Responses and system files" in System Settings > General > Software Update > Automatic Updates — this delivers XProtect/MRT definitions and Background Security Improvements.'
    else
        add_audit_result --category 'Software Update & Patch Compliance' --control 'Install Security Responses & System Files' \
            --status WARN --severity High --current "$current" "${fw[@]}" \
            --recommendation 'Enable "Install Security Responses and system files" (or toggle it off and on so the setting is auditable), or enforce both keys via profile.'
    fi
}

check_software_update_deferral() {
    evaluate_managed_pref --category 'Software Update & Patch Compliance' --control 'Software Update Deferral <= 30 Days' \
        --severity Medium --suite com.apple.applicationaccess --key enforcedSoftwareUpdateDelay --max 30 --unset-ok \
        --cis 'CIS 7.3, 7.4' --nist 'SI-2' --iso27001 'A.8.8' --nis2 'Art.21(2)(e)' \
        --cis-macos 'CIS-macOS 1.6' --mscp 'os_software_update_deferral' \
        --recommendation 'Reduce the Restrictions-profile enforcedSoftwareUpdateDelay to 30 days or fewer.'
}

check_rapid_security_response_state() {
    run_root sw_vers -productVersion

    # Always INFO: a trailing "(a)"/"(b)" suffix, when present, indicates
    # an applied Rapid Security Response — report the string as-is rather
    # than asserting a judgement, per honesty-over-false-precision.
    add_audit_result --category 'Software Update & Patch Compliance' --control 'Rapid Security Response State' \
        --status INFO --severity Informational --current "$ROOT_CMD_OUTPUT" \
        --recommended 'N/A' --cis-macos 'CIS-macOS 1.1' --mscp 'N/A' \
        --recommendation 'Informational only.'
}

# ---- 23-mdm-profiles.zsh ----
#
# Domain 14: MDM, Profiles & Supervision

check_mdm_enrollment_and_supervision() {
    write_section_banner 'MDM, Profiles & Supervision - MDM Enrollment & Supervision'
    run_root profiles status -type enrollment

    # Always INFO: enrollment state is environment-dependent, not a
    # pass/fail judgement — a personal, unenrolled Mac is not wrong.
    add_audit_result --category 'MDM, Profiles & Supervision' --control 'MDM Enrollment & Supervision' \
        --status INFO --severity Informational --current "$ROOT_CMD_OUTPUT" \
        --recommended 'N/A' \
        --cis 'CIS 12.5' --nist 'CM-8' --iso27001 'A.8.9' --nis2 'Art.21(2)(a)' --cis-macos 'CIS-macOS 5.10' --mscp 'N/A' \
        --recommendation 'Informational only. Confirm this matches the expected fleet-management state for this device.'
}

check_installed_profiles_inventory() {
    run_root profiles list -type configuration

    local -a lines identifiers=()
    lines=("${(@f)$(print -r -- "$ROOT_CMD_OUTPUT" | grep 'profileIdentifier')}")
    local l
    for l in "${lines[@]}"; do
        [[ -z "$l" ]] && continue
        identifiers+=("${l#*profileIdentifier: }")
    done
    local joined
    joined=$(printf '%s\n' "${identifiers[@]}")

    # Always INFO: this is inventory, not a judgement.
    add_audit_result --category 'MDM, Profiles & Supervision' --control 'Installed Profiles Inventory' \
        --status INFO --severity Informational --current "${#identifiers[@]} configuration profile(s) installed" \
        --details "$joined" \
        --recommended 'N/A' --cis-macos 'CIS-macOS 5.10' --mscp 'N/A' \
        --recommendation 'Informational only. Review the full profile list periodically for unrecognized or stale configuration profiles.'
}

# ---- 24-persistence.zsh ----
#
# Domain 15: Persistence Mechanisms & Auto-Runs

typeset -g PERSIST_CATEGORY='Persistence Mechanisms & Auto-Runs'

# Interpreters whose real launch target is the script they're handed,
# not themselves: an Apple-signed /bin/bash says nothing about the
# script it runs, so these targets are analyzed as scripts.
typeset -ga SCRIPT_INTERPRETERS
SCRIPT_INTERPRETERS=(sh bash zsh dash ksh csh tcsh python python2 python3 perl ruby osascript node php pwsh)

# "user<TAB>home" for every local human account (UID >= 501, not a
# _service account, home directory present). Separate so tests can stub it.
_local_user_homes() {
    local name="" uid="" home=""
    dscl . -list /Users UniqueID 2>/dev/null | while read -r name uid; do
        [[ "$uid" == <-> ]] && (( uid >= 501 )) || continue
        [[ "$name" == _* ]] && continue
        home=$(dscl . -read "/Users/$name" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
        [[ -n "$home" && -d "$home" ]] && print -r -- "$name"$'\t'"$home"
    done
}

# Masks credential-looking values (token=..., Bearer ..., password: ...)
# before a matched line is copied into the report.
_redact_secrets() {
    setopt localoptions extendedglob
    local line="$1"
    print -r -- "${line//(#ib)(token|secret|password|passwd|bearer|api[_-]#key)([\"' ]#[=: ][\"' ]#)[^\"' &|;]##/${match[1]}${match[2]}[REDACTED]}"
}

# Risk patterns for script content, matched against the lower-cased line.
# STRONG: download-and-execute, reverse shells, code injection, keychain
# or password theft (the AMOS / ClickFix playbook). WEAK: legitimate in
# places, but worth a look when it runs automatically.
typeset -ga SCRIPT_RISK_STRONG SCRIPT_RISK_WEAK
SCRIPT_RISK_STRONG=(
    '(curl|wget)[^|]*\|[[:space:]]*(sudo[[:space:]]+)?(ba|z|da|k)?sh([[:space:];]|$)'
    '(curl|wget)[^|]*\|[[:space:]]*(sudo[[:space:]]+)?(python[0-9.]*|perl|ruby|osascript|node)([[:space:]]|$)'
    'base64[[:space:]]+(-d|--decode)[^|]*\|[[:space:]]*(ba|z|da)?sh'
    'eval[^#]*base64'
    '/dev/tcp/'
    '(^|[^a-z])nc[[:space:]][^|]*-e[[:space:]]'
    'bash[[:space:]]+-i[[:space:]]*>&'
    'osascript[^#]*hidden answer'
    'dyld_insert_libraries'
    'security[[:space:]]+(find-generic-password|find-internet-password|dump-keychain)'
    'dscl[^#]*-authonly'
    'python[0-9.]*[[:space:]]+-c[^#]*(base64|exec\(|socket)'
)
SCRIPT_RISK_WEAK=(
    'osascript'
    '(^|[[:space:];])nohup[[:space:]]'
    '[^&]&[[:space:]]*(disown)?[[:space:]]*$'
    'launchctl[[:space:]]+(load|bootstrap|submit|setenv)'
    '(^|[^a-z0-9_])((/private)?/tmp/|(/private)?/var/tmp/|/users/shared/)'
    'xattr[^#]*com\.apple\.quarantine'
)

# Prints "STRONG|<n>: <line>" or "WEAK|<n>: <line>" for each non-comment
# line of the given text that matches a risk pattern.
_script_risk_scan_text() {
    local text="$1" line="" lower="" pat="" tier="" n=0
    for line in "${(@f)text}"; do
        n=$((n + 1))
        [[ "$line" =~ '^[[:space:]]*#' || -z "${line//[[:space:]]/}" ]] && continue
        lower="${(L)line}"
        tier=""
        for pat in "${SCRIPT_RISK_STRONG[@]}"; do
            [[ "$lower" =~ $pat ]] && { tier=STRONG; break; }
        done
        if [[ -z "$tier" ]]; then
            for pat in "${SCRIPT_RISK_WEAK[@]}"; do
                [[ "$lower" =~ $pat ]] && { tier=WEAK; break; }
            done
        fi
        [[ -n "$tier" ]] && print -r -- "$tier|$n: $(_redact_secrets "${${line##[[:space:]]#}[1,160]}")"
    done
}

_script_risk_scan_file() {
    [[ -f "$1" && -r "$1" ]] || return 0
    _script_risk_scan_text "$(< "$1")"
}

# Prints why a path could be tampered with by someone other than root /
# the expected owner (group/other-writable, or foreign owner); returns 1
# when it is fine. Checked for the file and its parent directory, since a
# writable directory lets anyone swap the file out.
_tamper_reason() {
    local f="$1" expected_owner="${2:-root}" target="" info="" owner="" mode=""
    for target in "$f" "${f:h}"; do
        info=$(stat -f '%Su %Lp' "$target" 2>/dev/null) || continue
        owner="${info% *}"; mode="${info#* }"
        if (( 8#$mode & 8#022 )); then
            print -r -- "$target writable by group/other (mode $mode)"; return 0
        fi
        if [[ "$owner" != root && "$owner" != "$expected_owner" ]]; then
            print -r -- "$target owned by $owner"; return 0
        fi
    done
    return 1
}

# Location-based risk: STRONG for world-writable staging areas, WEAK for
# hidden path components (common for dev tools, but also for stealers).
_risky_path_tier() {
    local path_="$1"
    case "$path_" in
        /tmp/*|/private/tmp/*|/var/tmp/*|/private/var/tmp/*|/Users/Shared/*) print STRONG ;;
        */.*) print WEAK ;;
        *) return 1 ;;
    esac
}

# "team <ID>", "apple", "ad-hoc", "unsigned" or "signed".
_code_signer() {
    local out=""
    out=$(codesign -dv "$1" 2>&1) || { print unsigned; return 0; }
    if [[ "$out" == *"Signature=adhoc"* ]]; then
        print ad-hoc
    elif [[ "$out" =~ 'TeamIdentifier=([A-Z0-9]+)' ]]; then
        print "team ${match[1]}"
    elif [[ "$out" == *"Platform identifier="* || "$out" == *"Authority=Software Signing"* ]]; then
        print apple
    else
        print signed
    fi
}

# Resolves what a launchd item actually runs. Sets REPLY_KIND (binary,
# script, inline), REPLY_PROGRAM, REPLY_SCRIPT (script path or inline
# command text). Handles Program vs ProgramArguments, /usr/bin/env, and
# interpreter flags (-c / -e mean the next argument is inline code).
_launchd_resolve_target() {
    local plist="$1" program="" arg="" base="" i=0 start=2
    local -a args
    program=$(plist_value_safe "$plist" Program '')
    for i in {0..31}; do
        arg=$(plist_value_safe "$plist" "ProgramArguments:$i") || break
        args+=("$arg")
    done
    [[ -z "$program" && ${#args[@]} -gt 0 ]] && program="${args[1]}"
    REPLY_PROGRAM="$program"; REPLY_KIND=binary; REPLY_SCRIPT=""

    base="${program:t}"
    if [[ "$base" == env && ${#args[@]} -ge 2 ]]; then
        base="${args[2]:t}"; start=3
    fi
    (( ${SCRIPT_INTERPRETERS[(Ie)$base]} )) || return 0

    for (( i = start; i <= ${#args[@]}; i++ )); do
        arg="${args[$i]}"
        if [[ "$arg" == -c || "$arg" == -e ]]; then
            REPLY_KIND=inline; REPLY_SCRIPT="${args[$((i + 1))]:-}"; return 0
        fi
        [[ "$arg" == -* ]] && continue
        REPLY_KIND=script; REPLY_SCRIPT="$arg"; return 0
    done
    REPLY_KIND=inline   # interpreter with no script: reads stdin/StandardInPath
}

# Per-scan accumulators, filled by _persistence_scan_collect and turned
# into one finding by _persistence_scan_report.
typeset -ga PERSIST_STRONG PERSIST_WEAK
typeset -gi PERSIST_TOTAL=0

_persistence_scan_reset() {
    PERSIST_STRONG=() PERSIST_WEAK=() PERSIST_TOTAL=0
}

# Assesses every launchd plist in one directory. root_run=1 for
# LaunchDaemons (anything able to modify the plist, program or script
# then gets root code execution). expected_owner is the account allowed
# to own the files (root for system dirs, the user for ~/Library).
_persistence_scan_collect() {
    local dir="$1" root_run="${2:-0}" expected_owner="${3:-root}"
    local -a plists
    plists=("$dir"/*.plist(ND))
    local p="" label="" item="" reason="" tier="" hit="" signer=""
    local -a strong weak
    for p in "${plists[@]}"; do
        strong=() weak=()
        label=$(plist_value_safe "$p" Label "${p:t:r}")
        _launchd_resolve_target "$p"

        # com.apple.* labels are skipped only when the target really is
        # Apple-signed; a com.apple.* label on anything else is classic
        # masquerading.
        if [[ "$label" == com.apple.* ]]; then
            if [[ "$REPLY_KIND" == binary && -e "$REPLY_PROGRAM" ]] && codesign -v -R='anchor apple' "$REPLY_PROGRAM" >/dev/null 2>&1; then
                continue
            fi
            strong+=("com.apple.* label but target is not Apple-signed")
        fi
        PERSIST_TOTAL=$((PERSIST_TOTAL + 1))

        [[ "${p:t}" == .* ]] && strong+=("hidden plist file")
        plist_value_safe "$p" 'EnvironmentVariables:DYLD_INSERT_LIBRARIES' >/dev/null \
            && strong+=("injects DYLD_INSERT_LIBRARIES")

        if [[ -n "$REPLY_PROGRAM" && "$REPLY_PROGRAM" == /* ]]; then
            if [[ ! -e "$REPLY_PROGRAM" ]]; then
                weak+=("target missing (orphaned item)")
            else
                tier=$(_risky_path_tier "$REPLY_PROGRAM") && {
                    [[ "$tier" == STRONG ]] && strong+=("target path under ${REPLY_PROGRAM:h}") || weak+=("target in hidden path")
                }
                if [[ "$REPLY_KIND" == binary ]]; then
                    if ! codesign -v "$REPLY_PROGRAM" >/dev/null 2>&1; then
                        strong+=("target binary fails code signature verification")
                    elif [[ "$(_code_signer "$REPLY_PROGRAM")" == ad-hoc && "$REPLY_PROGRAM" != /opt/homebrew/* && "$REPLY_PROGRAM" != /usr/local/Cellar/* ]]; then
                        weak+=("target is ad-hoc signed (no developer identity)")
                    fi
                    # A script run directly (shebang) still gets its content read.
                    if [[ "$(head -c 2 "$REPLY_PROGRAM" 2>/dev/null)" == '#!' ]]; then
                        REPLY_KIND=script; REPLY_SCRIPT="$REPLY_PROGRAM"
                    fi
                fi
            fi
        fi

        if [[ "$REPLY_KIND" == script && -n "$REPLY_SCRIPT" ]]; then
            if [[ "$REPLY_SCRIPT" == /* && ! -e "$REPLY_SCRIPT" ]]; then
                weak+=("script $REPLY_SCRIPT missing")
            else
                tier=$(_risky_path_tier "$REPLY_SCRIPT") && {
                    [[ "$tier" == STRONG ]] && strong+=("script under ${REPLY_SCRIPT:h}") || weak+=("script in hidden path $REPLY_SCRIPT")
                }
                for hit in "${(@f)$(_script_risk_scan_file "$REPLY_SCRIPT")}"; do
                    [[ -z "$hit" ]] && continue
                    [[ "$hit" == STRONG\|* ]] && strong+=("script ${hit#*|}") || weak+=("script ${hit#*|}")
                done
            fi
        elif [[ "$REPLY_KIND" == inline && -n "$REPLY_SCRIPT" ]]; then
            for hit in "${(@f)$(_script_risk_scan_text "$REPLY_SCRIPT")}"; do
                [[ -z "$hit" ]] && continue
                [[ "$hit" == STRONG\|* ]] && strong+=("inline command: ${hit#*|: }") || weak+=("inline command: ${hit#*|: }")
            done
        fi

        if [[ "$root_run" -eq 1 ]]; then
            for item in "$p" "$REPLY_PROGRAM" "$REPLY_SCRIPT"; do
                [[ "$item" == /* && -e "$item" ]] || continue
                # System binaries live on the sealed volume; skip them.
                [[ "$item" == /System/* || "$item" == /bin/* || "$item" == /usr/bin/* || "$item" == /usr/sbin/* || "$item" == /sbin/* ]] && continue
                reason=$(_tamper_reason "$item" root) && strong+=("root-run item modifiable: $reason")
            done
        elif [[ "$expected_owner" != root ]]; then
            # Another account able to edit this user's agent can run code
            # in that user's session.
            reason=$(_tamper_reason "$p" "$expected_owner") && strong+=("agent plist modifiable by another account: $reason")
        fi

        item="$label (${REPLY_SCRIPT:-$REPLY_PROGRAM})"
        if [[ ${#strong[@]} -gt 0 ]]; then
            PERSIST_STRONG+=("$item: ${(j:; :)strong}${weak:+; ${(j:; :)weak}}")
        elif [[ ${#weak[@]} -gt 0 ]]; then
            PERSIST_WEAK+=("$item: ${(j:; :)weak}")
        fi
    done
}

_persistence_scan_report() {
    local control_label="$1"
    local -a fw
    fw=(--recommended 'Every third-party launch item runs a signed program or a reviewed script from a protected location'
        --cis 'CIS 2.5, 2.7' --nist 'CM-7(5), SI-4, SI-7'
        --mitre 'T1543.001 (Launch Agent), T1543.004 (Launch Daemon), T1647 (Plist File Modification)'
        --iso27001 'A.8.19' --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 5.6' --mscp 'os_launch_items_review')

    if [[ ${#PERSIST_STRONG[@]} -gt 0 ]]; then
        add_audit_result --category "$PERSIST_CATEGORY" --control "$control_label" \
            --status FAIL --severity High --current "${(j: | :)PERSIST_STRONG}" \
            --details "${(F)PERSIST_STRONG}${PERSIST_WEAK:+$'\n'${(F)PERSIST_WEAK}}" "${fw[@]}" \
            --recommendation 'Investigate and remove the listed launch items unless independently verified as legitimate. An unsigned, /tmp-hosted, masquerading or tamperable persistent launch target, or a script with download-and-execute / credential-theft patterns, is a strong persistence-malware indicator. Capture the plist and target for forensics before removing.'
    elif [[ ${#PERSIST_WEAK[@]} -gt 0 ]]; then
        add_audit_result --category "$PERSIST_CATEGORY" --control "$control_label" \
            --status WARN --severity Medium --current "$PERSIST_TOTAL third-party launch item(s) scanned, ${#PERSIST_WEAK[@]} need review" \
            --details "${(F)PERSIST_WEAK}" "${fw[@]}" \
            --recommendation 'Review the listed items: orphaned registrations, ad-hoc-signed targets, hidden paths and scripts that background processes or call osascript/launchctl are common in both legitimate tools and malware.'
    else
        add_audit_result --category "$PERSIST_CATEGORY" --control "$control_label" \
            --status PASS --severity High --current "$PERSIST_TOTAL third-party launch item(s) scanned, none suspicious" \
            "${fw[@]}" --recommendation 'No action required.'
    fi
}

_persistence_scan_dir() {
    local dir="$1" control_label="$2" root_run="${3:-0}"
    _persistence_scan_reset
    _persistence_scan_collect "$dir" "$root_run" root
    _persistence_scan_report "$control_label"
}

check_system_launch_daemons_integrity() {
    write_section_banner 'Persistence Mechanisms & Auto-Runs - System LaunchDaemons'
    _persistence_scan_dir '/Library/LaunchDaemons' 'System LaunchDaemon Integrity' 1
}

check_system_launch_agents_integrity() {
    _persistence_scan_dir '/Library/LaunchAgents' 'System LaunchAgent Integrity'
}

check_user_launch_agents_integrity() {
    # Every local account, not just the console user: a stealer that
    # infected another account persists there too.
    local entry="" user="" home=""
    local -a homes
    homes=("${(@f)$(_local_user_homes)}")
    homes=(${homes:#})
    if [[ ${#homes[@]} -eq 0 ]]; then
        add_audit_result --category "$PERSIST_CATEGORY" --control 'User LaunchAgent Integrity' \
            --status WARN --severity Low --current 'No local user home directories found' \
            --recommended 'Scan completes against every local user account' \
            --cis-macos 'CIS-macOS 5.6' --mscp 'os_launch_items_review' \
            --recommendation 'Unable to enumerate local accounts with dscl; verify ~/Library/LaunchAgents manually for each user.'
        return
    fi
    _persistence_scan_reset
    for entry in "${homes[@]}"; do
        user="${entry%%$'\t'*}"; home="${entry#*$'\t'}"
        _persistence_scan_collect "$home/Library/LaunchAgents" 0 "$user"
    done
    _persistence_scan_report 'User LaunchAgent Integrity'
}

# `sfltool dumpbtm` takes ~20s; three checks read it, so it is loaded
# once per run. Prime with a direct call (not inside $(...)).
typeset -g BTM_DUMP=""
typeset -gi BTM_DUMP_STATUS=-1

load_btm_dump() {
    if [[ $BTM_DUMP_STATUS -lt 0 ]]; then
        BTM_DUMP=$(sfltool dumpbtm 2>&1)
        BTM_DUMP_STATUS=$?
    fi
    return $BTM_DUMP_STATUS
}

check_login_items_inventory() {
    load_btm_dump
    local ROOT_CMD_OUTPUT="$BTM_DUMP" ROOT_CMD_STATUS=$BTM_DUMP_STATUS

    if [[ "$ROOT_CMD_STATUS" -ne 0 ]]; then
        add_audit_result --category 'Persistence Mechanisms & Auto-Runs' --control 'Login Items & Background Task Inventory' \
            --status WARN --severity Low --current "sfltool query failed: $ROOT_CMD_OUTPUT" \
            --recommended 'N/A' --cis-macos 'CIS-macOS 5.6' --mscp 'N/A' \
            --recommendation 'Unable to query login items; verify manually with "sfltool dumpbtm" in Terminal.'
        return
    fi

    local count
    # Real `sfltool dumpbtm` output (verified live) numbers each top-level
    # item as exactly one leading space, "#<N>:", then end of line — e.g.
    # " #3:". A 4+-space-indented "#<N>: <identifier>" line (with trailing
    # content) is a nested "Embedded Item Identifiers:" reference to an
    # existing item, not a separate registered item; the naive pattern
    # "^[[:space:]]*#[0-9]+:" matches both and overcounts by ~19% on a real
    # machine with grouped apps (Office, OneDrive, Edge, etc.) — verified
    # live: 56 matches with the naive pattern vs. 47 genuine top-level items
    # with this anchored one.
    count=$(print -r -- "$ROOT_CMD_OUTPUT" | grep -cE '^ #[0-9]+:$')

    # Capture the Name value that follows each top-level "#N:" marker for
    # the hover tooltip — but only the first Name line after each marker
    # and before the next one, so a nested "Embedded Item Identifiers:"
    # entry's own Name line (if any) never gets attributed to the
    # top-level item as a duplicate.
    local -a names=()
    local in_item=0 line
    for line in "${(@f)ROOT_CMD_OUTPUT}"; do
        if [[ "$line" =~ '^ #[0-9]+:$' ]]; then
            in_item=1
            continue
        fi
        if (( in_item )) && [[ "$line" =~ '^[[:space:]]*Name: (.+)$' ]]; then
            names+=("${match[1]}")
            in_item=0
        fi
    done
    local joined
    joined=$(printf '%s\n' "${names[@]}")

    add_audit_result --category 'Persistence Mechanisms & Auto-Runs' --control 'Login Items & Background Task Inventory' \
        --status INFO --severity Informational --current "$count background/login item(s) registered" \
        --details "$joined" \
        --recommended 'N/A' --cis-macos 'CIS-macOS 5.6' --mscp 'N/A' \
        --recommendation 'Informational only. Periodically review "sfltool dumpbtm" output and remove unrecognized login items in System Settings > General > Login Items.'
}

check_login_logout_hooks() {
    if [[ -z "$CONSOLE_USER" ]]; then
        add_audit_result --category 'Persistence Mechanisms & Auto-Runs' --control 'Login/Logout Hooks' \
            --status WARN --severity Low --current 'No console user detected' \
            --recommended 'No LoginHook/LogoutHook configured' \
            --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'Re-run interactively at a console login session to evaluate login/logout hooks.'
        return
    fi

    local login_hook logout_hook
    login_hook=$(defaults_read_as_user_safe 'com.apple.loginwindow' 'LoginHook' '')
    logout_hook=$(defaults_read_as_user_safe 'com.apple.loginwindow' 'LogoutHook' '')

    if [[ -n "$login_hook" || -n "$logout_hook" ]]; then
        add_audit_result --category 'Persistence Mechanisms & Auto-Runs' --control 'Login/Logout Hooks' \
            --status WARN --severity Medium --current "LoginHook=${login_hook:-none}; LogoutHook=${logout_hook:-none}" \
            --recommended 'No LoginHook/LogoutHook configured' \
            --cis 'CIS 2.5' --nist 'CM-7' --mitre 'T1037.002 (Boot or Logon Initialization Scripts: Logon Script - Mac)' --iso27001 'A.8.19' \
            --nis2 'Art.21(2)(d)' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'This legacy per-user persistence mechanism runs a script at login/logout with the user'"'"'s privileges; confirm the referenced script is expected and remove it with "defaults delete com.apple.loginwindow LoginHook" (or LogoutHook) if not.'
    else
        add_audit_result --category 'Persistence Mechanisms & Auto-Runs' --control 'Login/Logout Hooks' \
            --status PASS --severity Medium --current 'No LoginHook/LogoutHook configured' \
            --recommended 'No LoginHook/LogoutHook configured' \
            --cis 'CIS 2.5' --nist 'CM-7' --mitre 'T1037.002 (Boot or Logon Initialization Scripts: Logon Script - Mac)' --iso27001 'A.8.19' \
            --nis2 'Art.21(2)(d)' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'No action required.'
    fi
}

# ---- 24b-persistence-extended.zsh ----
#
# Domain 15 (continued): Persistence Mechanisms & Auto-Runs — shell
# startup files, the wider persistence inventory, and a full autostart
# app/script audit. Shares helpers with 24-persistence.zsh
# (_local_user_homes, _script_risk_scan_*, _tamper_reason, _code_signer,
# _launchd_resolve_target, load_btm_dump).
#
# Status convention for every check here: a STRONG indicator (download-
# and-execute, credential theft, unsigned code, tamperable root-run item)
# is FAIL/High; presence of a rarely-legitimate mechanism or a WEAK
# indicator is WARN for review; nothing found is PASS.

# Reports a three-tier persistence finding from strong/weak item lists.
_persistence_tiered_result() {
    # $5/$6 name the caller's strong/weak arrays. Copied into
    # differently-named locals: declaring "local strong" here first would
    # shadow the caller's array before (P) could dereference it.
    local control="$1" pass_current="$2" warn_severity="$3" recommendation="$4"; shift 4
    local -a hi lo fw
    hi=("${(@P)1}"); lo=("${(@P)2}"); shift 2
    fw=("$@")
    hi=(${hi:#}); lo=(${lo:#})
    if [[ ${#hi[@]} -gt 0 ]]; then
        add_audit_result --category "$PERSIST_CATEGORY" --control "$control" \
            --status FAIL --severity High --current "${#hi[@]} high-risk item(s)${lo:+, ${#lo[@]} to review}" \
            --details "${(F)hi}${lo:+$'\n'${(F)lo}}" "${fw[@]}" --recommendation "$recommendation"
    elif [[ ${#lo[@]} -gt 0 ]]; then
        add_audit_result --category "$PERSIST_CATEGORY" --control "$control" \
            --status WARN --severity "$warn_severity" --current "${#lo[@]} item(s) to review" \
            --details "${(F)lo}" "${fw[@]}" --recommendation "$recommendation"
    else
        add_audit_result --category "$PERSIST_CATEGORY" --control "$control" \
            --status PASS --severity High --current "$pass_current" "${fw[@]}" --recommendation 'No action required.'
    fi
}

# Splits _script_risk_scan_* output for one source into the caller's
# `strong` / `weak` arrays, prefixed with a location label.
_collect_risk_hits() {
    local label="$1" hits="$2" hit=""
    for hit in "${(@f)hits}"; do
        [[ -z "$hit" ]] && continue
        if [[ "$hit" == STRONG\|* ]]; then strong+=("$label:${hit#*|}"); else weak+=("$label:${hit#*|}"); fi
    done
}

# ---------------------------------------------------------------------------
# Shell startup files (MITRE T1546.004). BlueNoroff used ~/.zshenv; the
# XCSSET variant makes ~/.zshrc source a hidden ~/.zshrc_aliases — so
# literal paths the startup files `source` are followed one level deep.
# ---------------------------------------------------------------------------

typeset -ga SHELL_STARTUP_USER_FILES SHELL_STARTUP_SYSTEM_FILES
SHELL_STARTUP_USER_FILES=(.zshenv .zprofile .zshrc .zlogin .zlogout .bash_profile .bash_login .bashrc .bash_logout .profile)
SHELL_STARTUP_SYSTEM_FILES=(zshenv zprofile zshrc zlogin zlogout profile bashrc)

# Resolves a `source`/`.` argument to an absolute path, or returns 1 when
# it depends on anything other than ~ / $HOME (not statically knowable).
_resolve_sourced_path() {
    local arg="$1" home="$2"
    arg="${${arg#[\"\']}%[\"\']}"
    if [[ -n "$home" ]]; then
        arg="${arg/#\~/$home}"; arg="${arg//\$\{HOME\}/$home}"; arg="${arg//\$HOME/$home}"
    fi
    [[ "$arg" == /* && "$arg" != *'$'* ]] || return 1
    print -r -- "$arg"
}

# Prints "owner<TAB>path" for every existing startup file: system files in
# etc_root, each local user's dotfiles (plus their ZDOTDIR's, if set), and
# any file those source by literal path.
_shell_startup_files() {
    local etc_root="$1" entry="" user="" home="" f="" d="" zdotdir="" line="" src=""
    local -a found dirs
    local -A seen home_of
    for f in "${SHELL_STARTUP_SYSTEM_FILES[@]}"; do
        [[ -f "$etc_root/$f" ]] && found+=("root"$'\t'"$etc_root/$f")
    done
    for entry in "${(@f)$(_local_user_homes)}"; do
        [[ -z "$entry" ]] && continue
        user="${entry%%$'\t'*}"; home="${entry#*$'\t'}"
        home_of[$user]="$home"
        dirs=("$home")
        zdotdir=$(grep -hE '^[[:space:]]*(export[[:space:]]+)?ZDOTDIR=' "$etc_root/zshenv" "$home/.zshenv" 2>/dev/null | tail -1)
        zdotdir="${${zdotdir#*ZDOTDIR=}%%[[:space:];]*}"
        zdotdir=$(_resolve_sourced_path "$zdotdir" "$home") && [[ -d "$zdotdir" && "$zdotdir" != "$home" ]] && dirs+=("$zdotdir")
        for d in "${dirs[@]}"; do
            for f in "${SHELL_STARTUP_USER_FILES[@]}"; do
                [[ -f "$d/$f" ]] && found+=("$user"$'\t'"$d/$f")
            done
        done
    done

    local -a with_sourced
    local owner="" file="" owner_home=""
    for entry in "${found[@]}"; do
        owner="${entry%%$'\t'*}"; file="${entry#*$'\t'}"
        [[ -n "${seen[$file]:-}" ]] && continue
        seen[$file]=1; with_sourced+=("$entry")
        owner_home="${home_of[$owner]:-}"
        # `source X` / `. X` anywhere on a line, including the XCSSET form
        # `[ -f ~/.zshrc_aliases ] && source ~/.zshrc_aliases`.
        for line in "${(@f)$(grep -v '^[[:space:]]*#' "$file" 2>/dev/null \
                | grep -oE '(^|[;&|[:space:]])(source|\.)[[:space:]]+[^[:space:];&|]+')}"; do
            [[ -z "$line" ]] && continue
            src="${line##*[[:space:]]}"
            src=$(_resolve_sourced_path "$src" "$owner_home") || continue
            [[ -f "$src" && -z "${seen[$src]:-}" ]] || continue
            seen[$src]=1; with_sourced+=("$owner"$'\t'"$src")
        done
    done
    print -rl -- "${with_sourced[@]}"
}

_shell_startup_content_check() {
    setopt localoptions extendedglob
    local etc_root="$1" entry="" file="" accounts=0
    local -a files strong weak
    files=("${(@f)$(_shell_startup_files "$etc_root")}"); files=(${files:#})
    for entry in "${files[@]}"; do
        file="${entry#*$'\t'}"
        _collect_risk_hits "$file" "$(_script_risk_scan_file "$file")"
    done
    [[ -f "$etc_root/zshenv" ]] && weak+=("$etc_root/zshenv: non-default system-wide file, read by every zsh including root scripts")
    accounts=${#${(u)${files[@]%%$'\t'*}}}

    _persistence_tiered_result 'Shell Startup File Content' \
        "${#files[@]} startup file(s) scanned across $accounts account(s), no suspicious commands" Medium \
        'Review each listed line. Download-and-execute, base64-decoded execution, reverse shells, keychain or password access and DYLD injection in a shell startup file run on every new terminal and are a known persistence technique (BlueNoroff ~/.zshenv, XCSSET .zshrc). Capture the file for forensics, then remove the line.' \
        strong weak \
        --recommended 'Shell startup files contain no download-and-execute, injection or credential-access commands' \
        --cis 'CIS 2.7' --nist 'SI-4, SI-7, CM-7(5)' --mitre 'T1546.004 (Unix Shell Configuration Modification)' \
        --iso27001 'A.8.7' --nis2 'Art.21(2)(d)' --cis-macos 'N/A' --mscp 'N/A'
}

check_shell_startup_file_content() {
    write_section_banner 'Persistence Mechanisms & Auto-Runs - Shell Startup Files & Extended Inventory'
    _shell_startup_content_check /private/etc
}

_shell_startup_permissions_check() {
    local etc_root="$1" entry="" owner="" file="" reason=""
    local -a files strong weak
    files=("${(@f)$(_shell_startup_files "$etc_root")}"); files=(${files:#})
    for entry in "${files[@]}"; do
        owner="${entry%%$'\t'*}"; file="${entry#*$'\t'}"
        reason=$(_tamper_reason "$file" "$owner") && strong+=("$file: $reason")
    done
    _persistence_tiered_result 'Shell Startup File Permissions' \
        "${#files[@]} startup file(s) writable only by their owner" Medium \
        'Restrict each listed file (and its directory) to its owner: "chmod go-w <file>"; system files under /etc must be owned by root. Anyone able to edit a startup file runs code as that user (or as root, for /etc files) on the next shell.' \
        strong weak \
        --recommended 'Startup files owned by their account (root for /etc) and not group/other-writable' \
        --cis 'CIS 3.3' --nist 'AC-3, CM-5' --mitre 'T1546.004 (Unix Shell Configuration Modification)' \
        --iso27001 'A.8.3' --nis2 'Art.21(2)(i)' --cis-macos 'N/A' --mscp 'N/A'
}

check_shell_startup_file_permissions() {
    _shell_startup_permissions_check /private/etc
}

# ---------------------------------------------------------------------------
# Wider persistence inventory
# ---------------------------------------------------------------------------

# Code bundles loaded into a privileged host process (SecurityAgent /
# opendirectoryd). A stock Mac has none in /Library; any entry runs in the
# login path, so unsigned is FAIL and signed third-party is WARN for review.
_plugin_bundle_dir_check() {
    local dir="$1" control="$2" mitre="$3" purpose="$4" e="" signer=""
    local -a entries strong weak
    entries=("$dir"/*(ND))
    for e in "${entries[@]}"; do
        signer=$(_code_signer "$e")
        if [[ "$signer" == unsigned ]] || ! codesign -v "$e" >/dev/null 2>&1; then
            strong+=("${e:t}: fails code signature verification ($signer)")
        else
            weak+=("${e:t}: $signer")
        fi
    done
    _persistence_tiered_result "$control" "No third-party plugins in $dir" Medium \
        "Confirm each listed plugin belongs to a sanctioned product ($purpose). Unknown plugins in this location run inside the login/authentication path and can capture credentials; remove them and restore the default authorization rights." \
        strong weak \
        --recommended "No unexpected plugins in $dir" --cis 'CIS 2.5' --nist 'IA-2, SI-7, CM-7(5)' \
        --mitre "$mitre" --iso27001 'A.8.5' --nis2 'Art.21(2)(i)' --cis-macos 'N/A' --mscp 'N/A'
}

check_authorization_plugins() {
    _plugin_bundle_dir_check /Library/Security/SecurityAgentPlugins 'Authorization Plugins' \
        'T1556 (Modify Authentication Process)' 'typically Platform SSO, Jamf Connect, NoMAD or smart-card middleware'
}

check_directory_services_plugins() {
    _plugin_bundle_dir_check /Library/DirectoryServices/PlugIns 'Directory Services Plugins' \
        'T1556 (Modify Authentication Process)' 'typically a legacy directory-binding product'
}

_privileged_helper_tools_check() {
    local helpers_dir="$1" daemons_dir="$2" h="" signer="" reason=""
    local -a helpers strong weak inventory daemon_plists
    helpers=("$helpers_dir"/*(ND))
    daemon_plists=("$daemons_dir"/*.plist(ND))
    for h in "${helpers[@]}"; do
        signer=$(_code_signer "$h")
        inventory+=("${h:t}: $signer")
        if ! codesign -v "$h" >/dev/null 2>&1; then
            strong+=("${h:t}: fails code signature verification ($signer)")
        fi
        reason=$(_tamper_reason "$h" root) && strong+=("${h:t}: runs as root but $reason")
        if [[ ${#daemon_plists[@]} -eq 0 ]] || ! grep -qF -- "$h" "${daemon_plists[@]}" 2>/dev/null; then
            weak+=("${h:t}: orphaned (no LaunchDaemon references it; leftover from an uninstalled app)")
        fi
    done
    if [[ ${#strong[@]} -eq 0 && ${#weak[@]} -eq 0 ]]; then
        add_audit_result --category "$PERSIST_CATEGORY" --control 'Privileged Helper Tools' \
            --status PASS --severity High --current "${#helpers[@]} privileged helper(s), all signed and in use" \
            --details "${(F)inventory}" --recommended 'Every privileged helper signed, root-owned and referenced by a LaunchDaemon' \
            --cis 'CIS 2.5' --nist 'AC-6, SI-7' --mitre 'T1543.004 (Launch Daemon)' --iso27001 'A.8.19' \
            --nis2 'Art.21(2)(d)' --cis-macos 'N/A' --mscp 'N/A' --recommendation 'No action required.'
        return 0
    fi
    _persistence_tiered_result 'Privileged Helper Tools' '' Low \
        'Privileged helpers run as root on behalf of apps. Remove unsigned or tamperable helpers immediately; remove orphaned ones (and any matching LaunchDaemon plist) left behind by uninstalled apps.' \
        strong weak \
        --recommended 'Every privileged helper signed, root-owned and referenced by a LaunchDaemon' \
        --cis 'CIS 2.5' --nist 'AC-6, SI-7' --mitre 'T1543.004 (Launch Daemon)' --iso27001 'A.8.19' \
        --nis2 'Art.21(2)(d)' --cis-macos 'N/A' --mscp 'N/A'
}

check_privileged_helper_tools() {
    _privileged_helper_tools_check /Library/PrivilegedHelperTools /Library/LaunchDaemons
}

# Cron is still honored by macOS (cron daemon starts on demand) and at(1)
# jobs run if atrun is enabled; neither is used by a stock install.
_cron_at_jobs_check() {
    local tabs_dir="$1" system_crontab="$2" at_dir="$3" t="" line="" job="" hits=""
    local -a strong weak
    if [[ -d "$tabs_dir" && ! -r "$tabs_dir" ]]; then
        add_audit_result --category "$PERSIST_CATEGORY" --control 'Cron & at Jobs' \
            --status WARN --severity Low --current "Cannot read $tabs_dir (run as root)" \
            --recommended 'No unexpected cron or at jobs' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'Re-run with sudo, or check with "sudo crontab -l -u <user>" for each account.'
        return 0
    fi
    for t in "$tabs_dir"/*(N.) "$system_crontab"(N.); do
        for line in "${(@f)$(< "$t")}"; do
            [[ "$line" =~ '^[[:space:]]*(#|$)' || "$line" =~ '^[A-Za-z_]+=' ]] && continue
            hits=$(_script_risk_scan_text "$line")
            if [[ -n "$hits" ]]; then
                _collect_risk_hits "${t:t}" "$hits"
            else
                weak+=("${t:t}: $(_redact_secrets "${line[1,160]}")")
            fi
        done
    done
    for job in "$at_dir"/*(N.); do
        [[ "${job:t}" == .* ]] && continue
        weak+=("at job ${job:t}")
        _collect_risk_hits "at job ${job:t}" "$(_script_risk_scan_file "$job")"
    done
    _persistence_tiered_result 'Cron & at Jobs' 'No cron or at jobs scheduled' Medium \
        'Confirm each scheduled job is expected; "crontab -r -u <user>" removes a user'"'"'s table. Stock macOS schedules nothing via cron/at — launchd is the supported scheduler — so these are frequently overlooked persistence.' \
        strong weak \
        --recommended 'No unexpected cron or at jobs' --cis 'CIS 2.7' --nist 'CM-7, SI-4' \
        --mitre 'T1053.003 (Cron), T1053.002 (At)' --iso27001 'A.8.19' --nis2 'Art.21(2)(d)' --cis-macos 'N/A' --mscp 'N/A'
}

check_cron_and_at_jobs() {
    _cron_at_jobs_check /usr/lib/cron/tabs /etc/crontab /usr/lib/cron/jobs
}

# Periodic scripts shipped by macOS (when /etc/periodic exists at all — it
# is absent on Tahoe, verified live).
typeset -ga STOCK_PERIODIC_SCRIPTS
STOCK_PERIODIC_SCRIPTS=(110.clean-tmps 130.clean-msgs 140.clean-rwho 199.rotate-fax 310.accounting 400.status-disks
    420.status-network 430.status-rwho 999.local 310.locate 320.whatis 200.accounting)

_legacy_boot_scripts_check() {
    local etc_root="$1" startup_dir="$2" emond_clients_dir="$3" f="" period=""
    local -a candidates strong weak
    for period in daily weekly monthly; do
        for f in "$etc_root/periodic/$period"/*(N.); do
            (( ${STOCK_PERIODIC_SCRIPTS[(Ie)${f:t}]} )) || candidates+=("$f")
        done
        [[ -f "$etc_root/$period.local" ]] && candidates+=("$etc_root/$period.local")
    done
    for f in "$etc_root/periodic.conf" "$etc_root/rc.local" "$etc_root/launchd.conf"; do
        [[ -f "$f" ]] && candidates+=("$f")
    done
    candidates+=("$startup_dir"/*(ND))
    for f in "$etc_root/emond.d/rules"/*(N.); do
        [[ "${f:t}" == SampleRules.plist ]] || candidates+=("$f")
    done
    candidates+=("$emond_clients_dir"/*(ND))

    for f in "${candidates[@]}"; do
        weak+=("$f (modified $(stat -f '%Sm' -t '%Y-%m-%d' "$f" 2>/dev/null))")
        [[ -f "$f" ]] && _collect_risk_hits "$f" "$(_script_risk_scan_file "$f")"
    done
    _persistence_tiered_result 'Legacy Boot, Periodic & emond Scripts' \
        'No rc.local, StartupItems, non-stock periodic scripts or emond rules present' Medium \
        'These legacy mechanisms (rc.local, launchd.conf, StartupItems, periodic, emond) are unused on modern macOS, so any entry deserves scrutiny. Remove items you cannot attribute to a known product.' \
        strong weak \
        --recommended 'No legacy boot-time or periodic scripts beyond the macOS defaults' --cis 'CIS 2.7' \
        --nist 'CM-7, SI-4' --mitre 'T1037.004 (RC Scripts), T1037.005 (Startup Items), T1546.014 (Emond)' \
        --iso27001 'A.8.19' --nis2 'Art.21(2)(d)' --cis-macos 'N/A' --mscp 'N/A'
}

check_legacy_boot_and_periodic_scripts() {
    _legacy_boot_scripts_check /private/etc /Library/StartupItems /private/var/db/emondClients
}

# sshd runs ~/.ssh/rc (or /etc/ssh/sshrc) on every SSH login — rarely used
# legitimately, and invisible to Login Items / BTM.
_ssh_login_scripts_check() {
    local etc_ssh_dir="$1" root_home="$2" entry="" home="" f=""
    local -a files strong weak
    [[ -f "$etc_ssh_dir/sshrc" ]] && files+=("$etc_ssh_dir/sshrc")
    [[ -f "$root_home/.ssh/rc" ]] && files+=("$root_home/.ssh/rc")
    for entry in "${(@f)$(_local_user_homes)}"; do
        [[ -z "$entry" ]] && continue
        home="${entry#*$'\t'}"
        [[ -f "$home/.ssh/rc" ]] && files+=("$home/.ssh/rc")
    done
    for f in "${files[@]}"; do
        weak+=("$f: runs on every SSH login")
        _collect_risk_hits "$f" "$(_script_risk_scan_file "$f")"
    done
    _persistence_tiered_result 'SSH Login Scripts (sshrc)' 'No ~/.ssh/rc or /etc/ssh/sshrc present' Medium \
        'Review and remove unexpected SSH login scripts; they execute for every SSH session and do not appear in Login Items.' \
        strong weak \
        --recommended 'No SSH login scripts' --cis 'CIS 2.7' --nist 'CM-7, AC-17' \
        --mitre 'T1546 (Event Triggered Execution)' --iso27001 'A.8.19' --nis2 'Art.21(2)(d)' --cis-macos 'N/A' --mscp 'N/A'
}

check_ssh_login_scripts() {
    _ssh_login_scripts_check /private/etc/ssh /var/root
}

_ssh_authorized_keys_check() {
    local root_home="$1" entry="" user="" home="" f="" n=0
    local -a keys root_keys
    for entry in "root"$'\t'"$root_home" "${(@f)$(_local_user_homes)}"; do
        [[ -z "$entry" ]] && continue
        user="${entry%%$'\t'*}"; home="${entry#*$'\t'}"
        for f in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
            [[ -f "$f" ]] || continue
            n=$(grep -cvE '^[[:space:]]*(#|$)' "$f" 2>/dev/null)
            (( n > 0 )) || continue
            # Key comments (usually user@host) identify keys without
            # copying key material into the report.
            keys+=("$user: $n key(s) in ${f:t} — $(grep -vE '^[[:space:]]*(#|$)' "$f" | awk '{print $NF}' | head -5 | paste -sd ', ' -)")
            [[ "$user" == root ]] && root_keys+=("$f")
        done
    done
    local -a fw
    fw=(--recommended 'Only expected public keys authorized; none for root' --cis 'CIS 5.4, 6.3' --nist 'AC-2, IA-2'
        --mitre 'T1098.004 (SSH Authorized Keys)' --iso27001 'A.5.18' --nis2 'Art.21(2)(i)' --cis-macos 'N/A' --mscp 'N/A')
    if [[ ${#root_keys[@]} -gt 0 ]]; then
        add_audit_result --category "$PERSIST_CATEGORY" --control 'SSH Authorized Keys Inventory' \
            --status WARN --severity Medium --current 'root account accepts SSH public-key logins' \
            --details "${(F)keys}" "${fw[@]}" \
            --recommendation 'Remove root'"'"'s authorized_keys unless a documented automation needs it, and verify every other listed key belongs to its account owner. An added key is silent, password-less persistence.'
    elif [[ ${#keys[@]} -gt 0 ]]; then
        add_audit_result --category "$PERSIST_CATEGORY" --control 'SSH Authorized Keys Inventory' \
            --status INFO --severity Informational --current "${#keys[@]} account(s) authorize SSH public keys" \
            --details "${(F)keys}" "${fw[@]}" \
            --recommendation 'Verify every listed key belongs to its account owner; remove stale keys.'
    else
        add_audit_result --category "$PERSIST_CATEGORY" --control 'SSH Authorized Keys Inventory' \
            --status PASS --severity Medium --current 'No authorized_keys entries' "${fw[@]}" --recommendation 'No action required.'
    fi
}

check_ssh_authorized_keys_inventory() {
    _ssh_authorized_keys_check /var/root
}

# Python executes "import ..." lines in any .pth file in site-packages at
# every interpreter start, plus sitecustomize/usercustomize modules
# (MITRE T1546.018). Many packages ship benign import-.pth files, so only
# code-execution patterns are escalated.
typeset -ga PYTHON_PTH_RISK
PYTHON_PTH_RISK=('base64' 'exec\(' 'eval\(' 'urllib' 'socket' 'subprocess' 'os\.system' 'os\.popen' 'compile\(' 'marshal')

_python_site_dirs() {
    local entry="" home=""
    local -a dirs
    dirs=(/Library/Python/*/site-packages(N/) /Library/Frameworks/Python.framework/Versions/*/lib/python*/site-packages(N/)
          /opt/homebrew/lib/python*/site-packages(N/) /usr/local/lib/python*/site-packages(N/))
    for entry in "${(@f)$(_local_user_homes)}"; do
        [[ -z "$entry" ]] && continue
        home="${entry#*$'\t'}"
        dirs+=("$home"/Library/Python/*/lib/python/site-packages(N/) "$home"/.local/lib/python*/site-packages(N/))
    done
    print -rl -- "${dirs[@]}"
}

_python_startup_hooks_check() {
    local d="" f="" line="" pat="" import_pth=0
    local -a dirs strong weak
    dirs=("${(@f)$(_python_site_dirs)}"); dirs=(${dirs:#})
    for d in "${dirs[@]}"; do
        for f in "$d"/(sitecustomize|usercustomize).py(N.); do
            weak+=("$f: runs at every Python start")
            _collect_risk_hits "$f" "$(_script_risk_scan_file "$f")"
        done
        for f in "$d"/*.pth(N.); do
            for line in "${(@f)$(grep -E '^[[:space:]]*import[[:space:]]' "$f" 2>/dev/null)}"; do
                [[ -z "$line" ]] && continue
                import_pth=$((import_pth + 1))
                for pat in "${PYTHON_PTH_RISK[@]}"; do
                    if [[ "$line" =~ $pat ]]; then
                        strong+=("$f: $(_redact_secrets "${line[1,160]}")"); break
                    fi
                done
            done
        done
    done
    _persistence_tiered_result 'Python Startup Hooks' \
        "${#dirs[@]} site-packages dir(s) scanned; $import_pth .pth import line(s), none executing code" Medium \
        'Inspect each listed file. A .pth import line that decodes, downloads or spawns processes runs on every Python start; remove the file (and the package that dropped it) if it is not expected.' \
        strong weak \
        --recommended 'No code-executing .pth files or unexpected sitecustomize/usercustomize modules' --cis 'CIS 2.7' \
        --nist 'SI-7, CM-7(5)' --mitre 'T1546.018 (Python Startup Hooks)' --iso27001 'A.8.19' \
        --nis2 'Art.21(2)(d)' --cis-macos 'N/A' --mscp 'N/A'
}

check_python_startup_hooks() {
    _python_startup_hooks_check
}

# ---------------------------------------------------------------------------
# Autostart apps & scripts audit
# ---------------------------------------------------------------------------

# One "uid|type|disposition|name|path|team" line per top-level BTM item.
# Legacy items are the /Library/Launch* plists (already assessed by the
# launchd checks) and are emitted too; callers filter by type.
# SMAppService agents/daemons record "Executable Path" relative to their
# parent app (e.g. "Contents/MacOS/Helper", verified live), so a second
# pass resolves it through "Parent Identifier" -> the parent's URL.
_btm_records() {
    local line="" uid="" key="" value="" i=0 path_="" parent=""
    local -a r_uid r_type r_disp r_name r_path r_team r_parent
    local -A rec app_path
    _btm_store() {
        [[ -n "${rec[Type]:-}" ]] || return 0
        local url_path=""
        # URL is a plain path on Tahoe (absolute for apps, relative to the
        # parent for embedded items); older releases used file:// URLs.
        url_path="${rec[URL]:-}"
        [[ "$url_path" == '(null)' ]] && url_path=""
        if [[ "$url_path" == file://* ]]; then
            url_path="${url_path#file://}"; url_path=$(printf '%b' "${url_path//\%/\\x}")
        fi
        url_path="${url_path%/}"
        [[ "$url_path" == /* && -n "${rec[Identifier]:-}" ]] && app_path[${rec[Identifier]}]="$url_path"
        r_uid+=("$uid"); r_type+=("${rec[Type]% \(*}"); r_disp+=("${rec[Disposition]:-}")
        r_name+=("${rec[Name]:-}"); r_team+=("${rec[Team Identifier]:-}")
        r_path+=("${rec[Executable Path]:-$url_path}"); r_parent+=("${rec[Parent Identifier]:-}")
    }
    for line in "${(@f)BTM_DUMP}"; do
        if [[ "$line" =~ '^ Records for UID (-?[0-9]+)' ]]; then
            _btm_store; rec=(); uid="${match[1]}"
        elif [[ "$line" =~ '^ #[0-9]+:$' ]]; then
            _btm_store; rec=()
        elif [[ "$line" =~ '^ {1,20}([A-Z][A-Za-z. ]+): (.*)$' ]]; then
            key="${match[1]}"; value="${match[2]}"
            [[ -z "${rec[$key]:-}" ]] && rec[$key]="$value"
        fi
    done
    _btm_store
    unfunction _btm_store

    for (( i = 1; i <= ${#r_type[@]}; i++ )); do
        path_="${r_path[$i]}"; parent="${r_parent[$i]}"
        if [[ -n "$path_" && "$path_" != /* ]]; then
            if [[ -n "${app_path[$parent]:-}" ]]; then
                path_="${app_path[$parent]}/$path_"
            else
                path_="?/$path_"    # parent app not recorded: unresolvable, never "missing"
            fi
        fi
        print -r -- "${r_uid[$i]}|${r_type[$i]}|${r_disp[$i]}|${r_name[$i]}|$path_|${r_team[$i]}"
    done
}

# Enabled and allowed: "[enabled, disallowed, ...]" is an item the user
# switched off in Login Items & Extensions.
_btm_active() {
    [[ "$1" == 'login item' || "$1" == agent || "$1" == daemon ]] && [[ "$2" == *'[enabled, allowed'* ]]
}

check_btm_item_integrity() {
    local rec="" uid="" type="" disposition="" name="" target="" team="" tier=""
    local -a strong weak
    if ! load_btm_dump; then
        add_audit_result --category "$PERSIST_CATEGORY" --control 'Login Item & Background Task Integrity' \
            --status WARN --severity Low --current "sfltool query failed: $BTM_DUMP" \
            --recommended 'Every enabled login item and background task is signed and present' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'Unable to read Background Task Management records; verify with "sudo sfltool dumpbtm".'
        return 0
    fi
    for rec in "${(@f)$(_btm_records)}"; do
        IFS='|' read -r uid type disposition name target team <<< "$rec"
        _btm_active "$type" "$disposition" || continue
        local -a reasons_s=() reasons_w=()
        [[ -z "$team" ]] && reasons_w+=("no Team ID (unsigned or ad-hoc)")
        if [[ "$target" == '?/'* ]]; then
            :   # relative to an unrecorded parent app; cannot be located
        elif [[ -n "$target" && ! -e "$target" ]]; then
            reasons_w+=("target missing (orphaned registration)")
        elif [[ -n "$target" ]]; then
            tier=$(_risky_path_tier "$target") && {
                [[ "$tier" == STRONG ]] && reasons_s+=("runs from ${target:h}") || reasons_w+=("runs from a hidden path")
            }
            codesign -v "$target" >/dev/null 2>&1 || reasons_s+=("fails code signature verification")
        fi
        if [[ ${#reasons_s[@]} -gt 0 ]]; then
            strong+=("$name [$type, uid $uid] ($target): ${(j:; :)reasons_s}${reasons_w:+; ${(j:; :)reasons_w}}")
        elif [[ ${#reasons_w[@]} -gt 0 ]]; then
            weak+=("$name [$type, uid $uid] ($target): ${(j:; :)reasons_w}")
        fi
    done
    _persistence_tiered_result 'Login Item & Background Task Integrity' \
        'Every enabled login item and SMAppService agent/daemon is signed and present' Medium \
        'Disable unknown items in System Settings > General > Login Items & Extensions and remove the owning app. Unsigned or /tmp- and /Users/Shared-hosted background items are a common infostealer persistence pattern.' \
        strong weak \
        --recommended 'Every enabled login item and background task signed, present and outside staging directories' \
        --cis 'CIS 2.5' --nist 'CM-7(5), SI-7' --mitre 'T1547.015 (Login Items)' --iso27001 'A.8.19' \
        --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 5.6' --mscp 'N/A'
}

# Full cross-source inventory of what starts automatically, classified as
# program (signed binary/app) or script, with its signer. Recomputed
# rather than shared with the integrity checks so it stands alone.
check_autostart_inventory() {
    local dir="" scope="" p="" label="" entry="" user="" home="" rec="" uid="" type="" disposition="" name="" target="" team="" t="" line=""
    local -a lines scopes
    local programs=0 scripts=0
    scopes=("/Library/LaunchDaemons|LaunchDaemon" "/Library/LaunchAgents|LaunchAgent (all users)")
    for entry in "${(@f)$(_local_user_homes)}"; do
        [[ -z "$entry" ]] && continue
        user="${entry%%$'\t'*}"; home="${entry#*$'\t'}"
        scopes+=("$home/Library/LaunchAgents|LaunchAgent ($user)")
    done
    for entry in "${scopes[@]}"; do
        dir="${entry%%|*}"; scope="${entry#*|}"
        for p in "$dir"/*.plist(ND); do
            label=$(plist_value_safe "$p" Label "${p:t:r}")
            _launchd_resolve_target "$p"
            if [[ "$label" == com.apple.* && "$REPLY_KIND" == binary ]] && codesign -v -R='anchor apple' "$REPLY_PROGRAM" >/dev/null 2>&1; then
                continue
            fi
            case "$REPLY_KIND" in
                binary)
                    lines+=("[$scope] $label -> $REPLY_PROGRAM (program, $( [[ -e "$REPLY_PROGRAM" ]] && _code_signer "$REPLY_PROGRAM" || print missing))")
                    programs=$((programs + 1)) ;;
                script)
                    lines+=("[$scope] $label -> ${REPLY_PROGRAM:t} $REPLY_SCRIPT (script)"); scripts=$((scripts + 1)) ;;
                inline)
                    lines+=("[$scope] $label -> ${REPLY_PROGRAM:t} inline command: $(_redact_secrets "${REPLY_SCRIPT[1,100]}")"); scripts=$((scripts + 1)) ;;
            esac
        done
    done

    if load_btm_dump; then
        for rec in "${(@f)$(_btm_records)}"; do
            IFS='|' read -r uid type disposition name target team <<< "$rec"
            _btm_active "$type" "$disposition" || continue
            lines+=("[${(C)type}, uid $uid] $name -> ${target:-?} (program, $( [[ -n "$team" ]] && print -r -- "team $team" || print -r -- 'no Team ID'))")
            programs=$((programs + 1))
        done
    fi

    if [[ -d /usr/lib/cron/tabs && -r /usr/lib/cron/tabs ]]; then
        for t in /usr/lib/cron/tabs/*(N.); do
            for line in "${(@f)$(grep -vE '^[[:space:]]*(#|$)|^[A-Za-z_]+=' "$t" 2>/dev/null)}"; do
                [[ -z "$line" ]] && continue
                lines+=("[cron, ${t:t}] $(_redact_secrets "${line[1,120]}") (script)"); scripts=$((scripts + 1))
            done
        done
    fi

    for entry in "${(@f)$(_shell_startup_files /private/etc)}"; do
        [[ -z "$entry" ]] && continue
        lines+=("[Shell startup, ${entry%%$'\t'*}] ${entry#*$'\t'} (script, runs with every new shell)")
        scripts=$((scripts + 1))
    done

    add_audit_result --category "$PERSIST_CATEGORY" --control 'Autostart Inventory (Apps & Scripts)' \
        --status INFO --severity Informational \
        --current "$(( programs + scripts )) autostart item(s): $programs program(s), $scripts script(s)" \
        --details "${(F)${(@o)lines}}" \
        --recommended 'N/A' --cis 'CIS 2.1, 2.7' --nist 'CM-8' --iso27001 'A.5.9' --cis-macos 'CIS-macOS 5.6' --mscp 'N/A' \
        --recommendation 'Informational baseline of everything that starts automatically (launchd, login items, background tasks, cron, shell startup). Compare against a known-good machine; integrity problems are reported by the dedicated persistence checks.'
}

# ---- 25-priv-esc-fs.zsh ----
#
# Domain 16: Privilege Escalation: File & Directory Permissions

# Checks whether a directory is group- or other-writable. Directly
# testable: create a scratch dir and chmod it.
_writable_dir_check() {
    local dir="$1" control_name="$2"
    run_root stat -f '%Lp' "$dir"

    if [[ $ROOT_CMD_STATUS -ne 0 ]]; then
        add_audit_result --category 'Privilege Escalation: File & Directory Permissions' --control "$control_name" \
            --status WARN --severity Low --current "stat query failed or directory missing: $ROOT_CMD_OUTPUT" \
            --recommended 'No group/other write bit' \
            --cis-macos 'CIS-macOS 5.6' --mscp 'N/A' \
            --recommendation "Unable to verify permissions for $dir; check manually with \"stat -f '%Lp' $dir\"."
        return
    fi

    local mode="$ROOT_CMD_OUTPUT"
    local last3="${mode: -3}"
    local group_digit="${last3:1:1}" other_digit="${last3:2:1}"

    if (( (group_digit & 2) != 0 || (other_digit & 2) != 0 )); then
        add_audit_result --category 'Privilege Escalation: File & Directory Permissions' --control "$control_name" \
            --status FAIL --severity Critical --current "$dir mode $mode" \
            --recommended 'No group/other write bit' \
            --cis 'CIS 5.1' --nist 'AC-6, CM-6' --mitre 'T1574.010 (Services File Permissions Weakness)' --iso27001 'A.8.3' \
            --nis2 'Art.21(2)(d)' --nsa 'NSA/CISA macOS Hardening Guidance' --cis-macos 'CIS-macOS 5.6' --mscp 'N/A' \
            --recommendation "sudo chmod go-w $dir — a world/group-writable LaunchDaemons or LaunchAgents directory lets any local user plant a persistent root-level launch item."
    else
        add_audit_result --category 'Privilege Escalation: File & Directory Permissions' --control "$control_name" \
            --status PASS --severity Critical --current "$dir mode $mode" \
            --recommended 'No group/other write bit' \
            --cis 'CIS 5.1' --nist 'AC-6, CM-6' --mitre 'T1574.010 (Services File Permissions Weakness)' --iso27001 'A.8.3' \
            --nis2 'Art.21(2)(d)' --nsa 'NSA/CISA macOS Hardening Guidance' --cis-macos 'CIS-macOS 5.6' --mscp 'N/A' \
            --recommendation 'No action required.'
    fi
}

check_writable_launchd_directories() {
    write_section_banner 'Privilege Escalation: File & Directory Permissions - Writable Launchd Directories'
    _writable_dir_check '/Library/LaunchDaemons' 'LaunchDaemons Directory Permissions'
    _writable_dir_check '/Library/LaunchAgents' 'LaunchAgents Directory Permissions'
}

# Splits a ":"-joined path string and flags any existing directory
# writable by non-root: group/other write bit set, or owned by a
# non-root user with the owner-write bit set. Directly testable by
# passing a synthetic scratch-dir string instead of the real $PATH.
_writable_path_scan() {
    local path_string="$1"
    local -a dirs
    dirs=(${(s.:.)path_string})

    local -a writable=()
    local scanned=0 dir

    for dir in "${dirs[@]}"; do
        [[ -z "$dir" || ! -d "$dir" ]] && continue
        scanned=$((scanned + 1))

        run_root stat -f '%Su %Lp' "$dir"
        [[ $ROOT_CMD_STATUS -ne 0 ]] && continue

        local owner="${ROOT_CMD_OUTPUT%% *}" mode="${ROOT_CMD_OUTPUT##* }"
        local last3="${mode: -3}"
        local owner_digit="${last3:0:1}" group_digit="${last3:1:1}" other_digit="${last3:2:1}"

        local is_writable=0
        if [[ "$owner" != "root" ]] && (( (owner_digit & 2) != 0 )); then is_writable=1; fi
        if (( (group_digit & 2) != 0 || (other_digit & 2) != 0 )); then is_writable=1; fi

        (( is_writable )) && writable+=("$dir")
    done

    if (( ${#writable[@]} > 0 )); then
        local joined
        joined=$(printf '%s, ' "${writable[@]}")
        joined="${joined%, }"
        add_audit_result --category 'Privilege Escalation: File & Directory Permissions' --control 'Writable PATH Directories' \
            --status FAIL --severity High --current "$joined" \
            --recommended 'No PATH directory writable by a non-root user' \
            --cis 'CIS 5.1' --nist 'AC-6, CM-6' --mitre 'T1574.007 (PATH Interception)' --iso27001 'A.8.3' \
            --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 5.6' --mscp 'N/A' \
            --recommendation 'Run "sudo chmod go-w <dir>" on each listed directory, or remove it from $PATH — any user-writable $PATH entry ahead of /usr/bin is a classic PATH-hijack vector.'
    else
        add_audit_result --category 'Privilege Escalation: File & Directory Permissions' --control 'Writable PATH Directories' \
            --status PASS --severity High --current "$scanned director(y/ies) scanned, none writable by non-root" \
            --recommended 'No PATH directory writable by a non-root user' \
            --cis 'CIS 5.1' --nist 'AC-6, CM-6' --mitre 'T1574.007 (PATH Interception)' --iso27001 'A.8.3' \
            --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 5.6' --mscp 'N/A' \
            --recommendation 'No action required.'
    fi
}

check_writable_path_directories() {
    _writable_path_scan "$PATH"
}

# Pure prefix classification: is this an Apple system path, or does it
# fall outside /usr, /bin, /sbin, /System (i.e. under /Applications)?
_is_system_suid_path() {
    case "$1" in
        /usr/*|/bin/*|/sbin/*|/System/*) return 0 ;;
        *) return 1 ;;
    esac
}

# Bounded SUID/SGID scan, matching the original tool's
# "performance-bounded scans" principle. Directly testable against
# scratch directories instead of the whole real filesystem.
_suid_sgid_scan() {
    local -a dirs=("$@")
    run_root find "${dirs[@]}" -perm -4000 -o -perm -2000

    local -a found
    found=("${(@f)ROOT_CMD_OUTPUT}")

    local total=0
    local -a outside_list=()
    local f

    for f in "${found[@]}"; do
        # Skip blank lines and any find/stderr diagnostic noise (which
        # never starts with "/") merged in via run_root's 2>&1 capture.
        [[ "$f" != /* ]] && continue
        total=$((total + 1))
        _is_system_suid_path "$f" || outside_list+=("$f")
    done

    if (( ${#outside_list[@]} > 0 )); then
        local joined
        joined=$(printf '%s, ' "${outside_list[@]}")
        joined="${joined%, }"
        add_audit_result --category 'Privilege Escalation: File & Directory Permissions' --control 'SUID/SGID Binary Audit' \
            --status WARN --severity High --current "$joined" \
            --recommended 'No SUID/SGID binaries outside /usr, /bin, /sbin, /System' \
            --cis 'CIS 5.1' --nist 'AC-6, CM-6' --mitre 'T1548.001 (Setuid and Setgid)' --iso27001 'A.8.3' \
            --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 5.6' --mscp 'N/A' \
            --recommendation 'Review each non-system SUID/SGID binary; confirm it is expected and from a trusted vendor.'
    else
        add_audit_result --category 'Privilege Escalation: File & Directory Permissions' --control 'SUID/SGID Binary Audit' \
            --status PASS --severity High --current "$total SUID/SGID binaries scanned" \
            --recommended 'No SUID/SGID binaries outside /usr, /bin, /sbin, /System' \
            --cis 'CIS 5.1' --nist 'AC-6, CM-6' --mitre 'T1548.001 (Setuid and Setgid)' --iso27001 'A.8.3' \
            --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 5.6' --mscp 'N/A' \
            --recommendation 'No action required.'
    fi
}

check_suid_sgid_binary_audit() {
    _suid_sgid_scan /usr /bin /sbin /Applications
}

# --- CIS Apple macOS 26 Tahoe v1.0.0 section 5.1 (5.1.1, 5.1.5-5.1.7) ---
# Each takes its root path as a parameter so tests can point it at a
# scratch tree. Full-depth scans match the CIS audit commands exactly;
# measured live at ~1s each, within the performance-bounded-scans budget.

_world_writable_dirs_result() {
    local control="$1" severity="$2" cis_macos="$3" mscp_id="$4" recommendation="$5" scanned="$6"; shift 6
    local -a found
    found=("$@")
    local -a fw
    fw=(--recommended "No world-writable directories under $scanned" --cis 'CIS 3.3' --nist 'AC-3, AC-6'
        --mitre 'T1574 (Hijack Execution Flow)' --iso27001 'A.8.3' --nis2 'Art.21(2)(i)'
        --cis-macos "CIS-macOS $cis_macos" --mscp "$mscp_id")
    if [[ ${#found[@]} -eq 0 ]]; then
        add_audit_result --category 'Privilege Escalation - File & Directory Permissions' --control "$control" \
            --status PASS --severity "$severity" --current "No world-writable directories under $scanned" "${fw[@]}" \
            --recommendation 'No action required.'
    else
        add_audit_result --category 'Privilege Escalation - File & Directory Permissions' --control "$control" \
            --status FAIL --severity "$severity" --current "${#found[@]} world-writable director(ies) under $scanned" \
            --details "${(F)found}" "${fw[@]}" --recommendation "$recommendation"
    fi
}

_home_folders_secure_check() {
    local users_root="$1"
    local -a insecure
    insecure=(${(f)"$(find "$users_root" -mindepth 1 -maxdepth 1 -type d ! -perm 700 ! -perm 710 ! -perm 711 2>/dev/null \
        | grep -v '/Shared$' | grep -v '/Guest$')"})
    local -a fw
    fw=(--recommended 'Every home folder mode 700 (710/711 tolerated)' --cis 'CIS 3.3' --nist 'AC-3, AC-6'
        --mitre 'T1005 (Data from Local System)' --iso27001 'A.8.3' --nis2 'Art.21(2)(i)'
        --cis-macos 'CIS-macOS 5.1.1' --mscp 'os_home_folders_secure')

    if [[ ${#insecure[@]} -eq 0 ]]; then
        add_audit_result --category 'Privilege Escalation - File & Directory Permissions' --control 'Home Folders Secure' \
            --status PASS --severity Medium --current 'All home folders restrict other users' "${fw[@]}" \
            --recommendation 'No action required.'
    else
        local -a described
        local d
        for d in "${insecure[@]}"; do
            described+=("$d ($(stat -f '%Sp' "$d" 2>/dev/null))")
        done
        add_audit_result --category 'Privilege Escalation - File & Directory Permissions' --control 'Home Folders Secure' \
            --status FAIL --severity Medium --current "${#insecure[@]} home folder(s) readable by other users" \
            --details "${(F)described}" "${fw[@]}" \
            --recommendation 'Restrict each listed home folder: "sudo chmod -R og-rwx /Users/<username>" (use og-rw to keep traverse access if a service requires it).'
    fi
}

check_home_folders_secure() {
    _home_folders_secure_check /System/Volumes/Data/Users
}

_world_writable_applications_check() {
    local apps_root="$1"
    local -a found
    found=(${(f)"$(find "$apps_root" -iname '*.app' -type d -perm -2 2>/dev/null | grep -v 'Xcode.app')"})
    _world_writable_dirs_result 'System-Wide Applications Not World-Writable' High 5.1.5 \
        os_system_wide_applications_configure \
        'Remove world-write from each listed app bundle: "sudo chmod -R o-w /Applications/<name>.app" — any local user could otherwise replace its code.' \
        "$apps_root" "${found[@]}"
}

check_world_writable_applications() {
    _world_writable_applications_check /System/Volumes/Data/Applications
}

_world_writable_system_folder_check() {
    local system_root="$1"
    local -a found
    found=(${(f)"$(find "$system_root" -type d -perm -2 2>/dev/null | grep -vE 'downloadDir|locks')"})
    _world_writable_dirs_result 'No World-Writable Folders in /System' High 5.1.6 \
        os_world_writable_system_folder_configure \
        'Remove world-write from each listed folder: "sudo chmod -R o-w <folder>".' \
        "$system_root" "${found[@]}"
}

check_world_writable_system_folder() {
    _world_writable_system_folder_check /System/Volumes/Data/System
}

_world_writable_library_folder_check() {
    local library_root="$1"
    # Sticky-bit dirs (! -perm -1000) and SIP-protected ones are excluded, per CIS.
    local -a found
    found=(${(f)"$(find "$library_root" -type d -perm -002 ! -perm -1000 ! -xattrname com.apple.rootless 2>/dev/null)"})
    _world_writable_dirs_result 'No World-Writable Folders in /Library' Medium 5.1.7 \
        os_world_writable_library_folder_configure \
        'Remove world-write from each listed folder: "sudo chmod -R o-w <folder>" (some third-party installers create these deliberately; confirm with the vendor first).' \
        "$library_root" "${found[@]}"
}

check_world_writable_library_folder() {
    _world_writable_library_folder_check /Library
}

# ---- 26-dylib-hijack.zsh ----
#
# Domain 17: Dylib Hijacking & Code Injection

check_dyld_insert_libraries_global_env() {
    write_section_banner 'Dylib Hijacking & Code Injection - DYLD_INSERT_LIBRARIES Global Env'
    run_root launchctl getenv DYLD_INSERT_LIBRARIES

    # NOTE: the mSCP key below is matched exactly by Task 36's remediation
    # generator — keep it as-is, not "N/A", so the FAIL case gets a real
    # automated remediation command instead of falling through to the
    # manual-guidance default.
    if [[ -n "$ROOT_CMD_OUTPUT" ]]; then
        add_audit_result --category 'Dylib Hijacking & Code Injection' --control 'DYLD_INSERT_LIBRARIES Global Env' \
            --status FAIL --severity Critical --current "$ROOT_CMD_OUTPUT" \
            --recommended 'unset' \
            --cis 'CIS 2.7' --nist 'SI-7, CM-7' --mitre 'T1574.006 (Dynamic Linker Hijacking)' --iso27001 'A.8.19' \
            --nis2 'Art.21(2)(d)' --nsa 'NSA/CISA macOS Hardening Guidance' --cis-macos 'CIS-macOS 5.6' --mscp 'os_dyld_insert_libraries_unset' \
            --recommendation 'sudo launchctl unsetenv DYLD_INSERT_LIBRARIES — a globally-set DYLD_INSERT_LIBRARIES forces code injection into every subsequently launched dynamically-linked process.'
    else
        add_audit_result --category 'Dylib Hijacking & Code Injection' --control 'DYLD_INSERT_LIBRARIES Global Env' \
            --status PASS --severity Critical --current 'unset' \
            --recommended 'unset' \
            --cis 'CIS 2.7' --nist 'SI-7, CM-7' --mitre 'T1574.006 (Dynamic Linker Hijacking)' --iso27001 'A.8.19' \
            --nis2 'Art.21(2)(d)' --nsa 'NSA/CISA macOS Hardening Guidance' --cis-macos 'CIS-macOS 5.6' --mscp 'os_dyld_insert_libraries_unset' \
            --recommendation 'No action required.'
    fi
}

# Checks whether a dylib search-path directory is group/other-writable.
# Directly testable with a scratch dir. A missing directory is not a
# finding at all — no add_audit_result call — since it's normal for
# these optional paths not to exist.
_writable_dylib_dir_check() {
    local dir="$1"
    [[ ! -d "$dir" ]] && return

    run_root stat -f '%Lp' "$dir"
    [[ $ROOT_CMD_STATUS -ne 0 ]] && return

    local mode="$ROOT_CMD_OUTPUT"
    local last3="${mode: -3}"
    local group_digit="${last3:1:1}" other_digit="${last3:2:1}"

    if (( (group_digit & 2) != 0 || (other_digit & 2) != 0 )); then
        add_audit_result --category 'Dylib Hijacking & Code Injection' --control 'Writable Dylib Search Paths' \
            --status FAIL --severity High --current "$dir mode $mode" \
            --recommended 'No group/other write bit' \
            --cis 'CIS 2.7' --nist 'SI-7, CM-7' --mitre 'T1574.006 (Dynamic Linker Hijacking)' --iso27001 'A.8.19' \
            --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 5.6' --mscp 'N/A' \
            --recommendation "sudo chmod go-w $dir — a writable systemwide library search path lets any local user plant a hijacked dylib for any process that searches it."
    else
        add_audit_result --category 'Dylib Hijacking & Code Injection' --control 'Writable Dylib Search Paths' \
            --status PASS --severity High --current "$dir mode $mode" \
            --recommended 'No group/other write bit' \
            --cis 'CIS 2.7' --nist 'SI-7, CM-7' --mitre 'T1574.006 (Dynamic Linker Hijacking)' --iso27001 'A.8.19' \
            --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 5.6' --mscp 'N/A' \
            --recommendation 'No action required.'
    fi
}

check_writable_dylib_search_paths() {
    _writable_dylib_dir_check '/usr/local/lib'
    _writable_dylib_dir_check '/Library/Frameworks'
}

check_hardened_runtime_spotcheck() {
    run_root codesign -dv --verbose=4 /usr/bin/login

    local current
    if [[ "$ROOT_CMD_OUTPUT" == *"flags=0x10000(runtime)"* || "$ROOT_CMD_OUTPUT" == *"runtime"* ]]; then
        current='flags=runtime present'
    else
        current='runtime flag not detected — unexpected on a stock system binary'
    fi

    # Always INFO: system binaries are always hardened on a stock macOS
    # install; this is a sanity confirmation, not a user-controllable
    # setting — never manufacture a FAIL/WARN judgement from it.
    add_audit_result --category 'Dylib Hijacking & Code Injection' --control 'Hardened Runtime Spotcheck' \
        --status INFO --severity Informational --current "$current" \
        --recommended 'N/A' --cis-macos 'CIS-macOS 5.6' --mscp 'N/A' \
        --recommendation 'Informational only.'
}

# ---- 27-credential-exposure.zsh ----
#
# Domain 18: Credential Exposure & Secret Leaks
#
# Every check refactors its core logic into a helper taking a
# home-directory path, so tests point at a scratch directory instead of a
# real user's home.

_ssh_key_perms_check() {
    local home="$1"

    if [[ ! -d "$home/.ssh" ]]; then
        add_audit_result --category 'Credential Exposure & Secret Leaks' --control 'SSH Private Key Permissions' \
            --status PASS --severity High --current '0 key(s) checked' \
            --recommended 'All private keys mode 600' \
            --cis 'CIS 3.11' --nist 'IA-5, SC-28' --mitre 'T1552.004 (Private Keys)' --iso27001 'A.8.24' \
            --nis2 'Art.21(2)(h)' --nsa 'NSA/CISA Credential Hardening Guidance' --cis-macos 'CIS-macOS 5.6' --mscp 'N/A' \
            --recommendation 'No action required.'
        return
    fi

    run_as_user find "$home/.ssh" -maxdepth 1 -type f ! -name '*.pub'
    local -a keys
    keys=("${(@f)RUN_AS_USER_OUTPUT}")

    local total=0
    local -a overperm=()
    local k mode last3 group_digit other_digit

    for k in "${keys[@]}"; do
        [[ -z "$k" ]] && continue
        total=$((total + 1))
        run_as_user stat -f '%Lp' "$k"
        mode="$RUN_AS_USER_OUTPUT"
        last3="${mode: -3}"
        group_digit="${last3:1:1}" other_digit="${last3:2:1}"
        if [[ "$group_digit" != "0" || "$other_digit" != "0" ]]; then
            overperm+=("$k")
        fi
    done

    if (( ${#overperm[@]} > 0 )); then
        local joined
        joined=$(printf '%s, ' "${overperm[@]}")
        joined="${joined%, }"
        add_audit_result --category 'Credential Exposure & Secret Leaks' --control 'SSH Private Key Permissions' \
            --status WARN --severity High --current "$joined" \
            --recommended 'All private keys mode 600' \
            --cis 'CIS 3.11' --nist 'IA-5, SC-28' --mitre 'T1552.004 (Private Keys)' --iso27001 'A.8.24' \
            --nis2 'Art.21(2)(h)' --nsa 'NSA/CISA Credential Hardening Guidance' --cis-macos 'CIS-macOS 5.6' --mscp 'N/A' \
            --recommendation 'Run "chmod 600" on each listed private key.'
    else
        add_audit_result --category 'Credential Exposure & Secret Leaks' --control 'SSH Private Key Permissions' \
            --status PASS --severity High --current "$total key(s) checked" \
            --recommended 'All private keys mode 600' \
            --cis 'CIS 3.11' --nist 'IA-5, SC-28' --mitre 'T1552.004 (Private Keys)' --iso27001 'A.8.24' \
            --nis2 'Art.21(2)(h)' --nsa 'NSA/CISA Credential Hardening Guidance' --cis-macos 'CIS-macOS 5.6' --mscp 'N/A' \
            --recommendation 'No action required.'
    fi
}

check_ssh_private_key_permissions() {
    write_section_banner 'Credential Exposure & Secret Leaks - SSH Private Key Permissions'
    if [[ -z "$CONSOLE_USER" ]]; then
        add_audit_result --category 'Credential Exposure & Secret Leaks' --control 'SSH Private Key Permissions' \
            --status WARN --severity Low --current 'No console user detected' \
            --recommended 'N/A' --cis-macos 'CIS-macOS 5.6' --mscp 'N/A' \
            --recommendation 'Re-run interactively at a console login session to evaluate SSH key permissions.'
        return
    fi
    _ssh_key_perms_check "$(eval echo ~$CONSOLE_USER)"
}

_cloud_cli_creds_check() {
    local home="$1"
    local -a candidates=("$home/.aws/credentials" "$home/.config/gcloud/credentials.db" "$home/.azure/accessTokens.json")
    local -a found=()
    local f

    for f in "${candidates[@]}"; do
        run_as_user test -e "$f"
        [[ $RUN_AS_USER_STATUS -eq 0 ]] && found+=("$f")
    done

    if (( ${#found[@]} > 0 )); then
        local joined
        joined=$(printf '%s, ' "${found[@]}")
        joined="${joined%, }"
        add_audit_result --category 'Credential Exposure & Secret Leaks' --control 'Cloud CLI Credential Files' \
            --status WARN --severity Medium --current "$joined" \
            --recommended 'No long-lived cloud CLI credential files' \
            --cis 'CIS 3.11' --nist 'IA-5' --mitre 'T1552.001 (Credentials in Files)' --iso27001 'A.8.24' \
            --nis2 'Art.21(2)(h)' --cis-macos 'CIS-macOS 5.6' --mscp 'N/A' \
            --recommendation 'Prefer short-lived SSO/OIDC tokens over long-lived static credential files where the CLI supports it; ensure file permissions are 600.'
    else
        add_audit_result --category 'Credential Exposure & Secret Leaks' --control 'Cloud CLI Credential Files' \
            --status PASS --severity Medium --current 'No cloud CLI credential files found' \
            --recommended 'No long-lived cloud CLI credential files' \
            --cis 'CIS 3.11' --nist 'IA-5' --mitre 'T1552.001 (Credentials in Files)' --iso27001 'A.8.24' \
            --nis2 'Art.21(2)(h)' --cis-macos 'CIS-macOS 5.6' --mscp 'N/A' \
            --recommendation 'No action required.'
    fi
}

check_cloud_cli_credential_files() {
    if [[ -z "$CONSOLE_USER" ]]; then
        add_audit_result --category 'Credential Exposure & Secret Leaks' --control 'Cloud CLI Credential Files' \
            --status WARN --severity Low --current 'No console user detected' \
            --recommended 'N/A' --cis-macos 'CIS-macOS 5.6' --mscp 'N/A' \
            --recommendation 'Re-run interactively at a console login session to evaluate cloud CLI credential files.'
        return
    fi
    _cloud_cli_creds_check "$(eval echo ~$CONSOLE_USER)"
}

# Bounded: only the last 500 lines of each history file, never a full-file
# or recursive scan, matching the original tool's performance-bounded-
# scans principle. Reports only match-type and count — never the matched
# text itself, since that could echo a live credential into the report.
_shell_history_sweep_check() {
    local home="$1"
    local -a lines=()

    if [[ -f "$home/.zsh_history" ]]; then
        run_as_user tail -n 500 "$home/.zsh_history"
        lines+=("${(@f)RUN_AS_USER_OUTPUT}")
    fi
    if [[ -f "$home/.bash_history" ]]; then
        run_as_user tail -n 500 "$home/.bash_history"
        lines+=("${(@f)RUN_AS_USER_OUTPUT}")
    fi

    local aws_count=0 begin_count=0 password_count=0 apikey_count=0
    local line lower

    for line in "${lines[@]}"; do
        [[ -z "$line" ]] && continue
        lower="${line:l}"
        [[ "$line" =~ 'AKIA[A-Z0-9]{16}' ]] && aws_count=$((aws_count + 1))
        [[ "$line" == *"-----BEGIN"* ]] && begin_count=$((begin_count + 1))
        [[ "$lower" == *"password="* ]] && password_count=$((password_count + 1))
        [[ "$lower" == *"apikey="* || "$lower" == *"api_key="* ]] && apikey_count=$((apikey_count + 1))
    done

    local -a parts=()
    (( aws_count > 0 )) && parts+=("$aws_count possible AWS key pattern(s)")
    (( begin_count > 0 )) && parts+=("$begin_count possible private-key-block pattern(s)")
    (( password_count > 0 )) && parts+=("$password_count possible password= pattern(s)")
    (( apikey_count > 0 )) && parts+=("$apikey_count possible apikey= pattern(s)")

    if (( ${#parts[@]} > 0 )); then
        local joined
        joined=$(printf '%s, ' "${parts[@]}")
        joined="${joined%, } found in recent history"
        add_audit_result --category 'Credential Exposure & Secret Leaks' --control 'Shell History Secret Sweep' \
            --status WARN --severity High --current "$joined" \
            --recommended 'No secret-like patterns in recent shell history' \
            --cis 'CIS 3.11' --nist 'IA-5' --mitre 'T1552.001 (Credentials in Files)' --iso27001 'A.8.24' \
            --nis2 'Art.21(2)(h)' --cis-macos 'CIS-macOS 5.6' --mscp 'N/A' \
            --recommendation 'Rotate any credential that may have been typed into a shell prompt and clear it from history.'
    else
        add_audit_result --category 'Credential Exposure & Secret Leaks' --control 'Shell History Secret Sweep' \
            --status PASS --severity High --current 'No secret-like patterns found in recent shell history' \
            --recommended 'No secret-like patterns in recent shell history' \
            --cis 'CIS 3.11' --nist 'IA-5' --mitre 'T1552.001 (Credentials in Files)' --iso27001 'A.8.24' \
            --nis2 'Art.21(2)(h)' --cis-macos 'CIS-macOS 5.6' --mscp 'N/A' \
            --recommendation 'No action required.'
    fi
}

check_shell_history_secret_sweep() {
    if [[ -z "$CONSOLE_USER" ]]; then
        add_audit_result --category 'Credential Exposure & Secret Leaks' --control 'Shell History Secret Sweep' \
            --status WARN --severity Low --current 'No console user detected' \
            --recommended 'N/A' --cis-macos 'CIS-macOS 5.6' --mscp 'N/A' \
            --recommendation 'Re-run interactively at a console login session to evaluate shell history.'
        return
    fi
    _shell_history_sweep_check "$(eval echo ~$CONSOLE_USER)"
}

# Bounded to top-level only of Desktop and Downloads. Reports filenames
# only, never file content.
_sensitive_filename_sweep_check() {
    local home="$1"
    local -a found=()
    local dir m
    local -a matches

    for dir in "$home/Desktop" "$home/Downloads"; do
        [[ ! -d "$dir" ]] && continue
        run_as_user find "$dir" -maxdepth 1 \( -iname '*password*' -o -iname '*credential*' -o -name '*.pem' -o -iname '*.key' \)
        matches=("${(@f)RUN_AS_USER_OUTPUT}")
        for m in "${matches[@]}"; do
            [[ -n "$m" ]] && found+=("$m")
        done
    done

    if (( ${#found[@]} > 0 )); then
        local joined
        joined=$(printf '%s, ' "${found[@]}")
        joined="${joined%, }"
        add_audit_result --category 'Credential Exposure & Secret Leaks' --control 'Sensitive Filename Sweep' \
            --status WARN --severity Medium --current "$joined" \
            --recommended 'No sensitive filenames in Desktop/Downloads' \
            --cis 'CIS 3.11' --nist 'IA-5' --mitre 'T1552.001 (Credentials in Files)' --iso27001 'A.8.24' \
            --nis2 'Art.21(2)(h)' --cis-macos 'CIS-macOS 5.6' --mscp 'N/A' \
            --recommendation 'Relocate genuine secrets into Keychain or a secrets manager; delete stray exports.'
    else
        add_audit_result --category 'Credential Exposure & Secret Leaks' --control 'Sensitive Filename Sweep' \
            --status PASS --severity Medium --current 'No sensitive filenames found in Desktop/Downloads' \
            --recommended 'No sensitive filenames in Desktop/Downloads' \
            --cis 'CIS 3.11' --nist 'IA-5' --mitre 'T1552.001 (Credentials in Files)' --iso27001 'A.8.24' \
            --nis2 'Art.21(2)(h)' --cis-macos 'CIS-macOS 5.6' --mscp 'N/A' \
            --recommendation 'No action required.'
    fi
}

check_sensitive_filename_sweep() {
    if [[ -z "$CONSOLE_USER" ]]; then
        add_audit_result --category 'Credential Exposure & Secret Leaks' --control 'Sensitive Filename Sweep' \
            --status WARN --severity Low --current 'No console user detected' \
            --recommended 'N/A' --cis-macos 'CIS-macOS 5.6' --mscp 'N/A' \
            --recommendation 'Re-run interactively at a console login session to evaluate sensitive filenames.'
        return
    fi
    _sensitive_filename_sweep_check "$(eval echo ~$CONSOLE_USER)"
}

# ---- 28-screen-lock.zsh ----
#
# Domain 19: Screen Lock & Physical Access

check_screensaver_password_required() {
    write_section_banner 'Screen Lock & Physical Access - Screensaver Password'
    # defaults_read_as_user_safe silently falls back to the caller-supplied
    # default both when the key is genuinely unset (normal, expected — most
    # Macs never touch this key) AND when there's no console user to query
    # at all (a real "cannot determine" case, not "verified insecure").
    # Per the Global Constraints fault-isolation rule, those two must not
    # collapse into the same FAIL.
    if [[ -z "$CONSOLE_USER" ]]; then
        add_audit_result --category 'Screen Lock & Physical Access' --control 'Screensaver Password Requirement' \
            --status WARN --severity Low --current 'No console user detected' \
            --recommended 'askForPassword=1' \
            --cis-macos 'CIS-macOS 2.10.1' --mscp 'os_screensaver_password_enforce' \
            --recommendation 'Re-run interactively at a console login session to evaluate the screensaver password requirement.'
        return
    fi
    local value
    value=$(defaults_read_as_user_safe 'com.apple.screensaver' 'askForPassword' '0')

    if [[ "$value" == "1" ]]; then
        add_audit_result --category 'Screen Lock & Physical Access' --control 'Screensaver Password Requirement' \
            --status PASS --severity High --current 'askForPassword=1 (required)' --recommended 'askForPassword=1' \
            --cis 'CIS 4.2' --nist 'AC-11' --mitre 'T1078 (Valid Accounts)' --iso27001 'A.8.1' --nis2 'Art.21(2)(i)' \
            --cis-macos 'CIS-macOS 2.10.1' --mscp 'os_screensaver_password_enforce' \
            --recommendation 'No action required.'
    else
        add_audit_result --category 'Screen Lock & Physical Access' --control 'Screensaver Password Requirement' \
            --status FAIL --severity High --current "askForPassword=$value (not required)" --recommended 'askForPassword=1' \
            --cis 'CIS 4.2' --nist 'AC-11' --mitre 'T1078 (Valid Accounts)' --iso27001 'A.8.1' --nis2 'Art.21(2)(i)' \
            --cis-macos 'CIS-macOS 2.10.1' --mscp 'os_screensaver_password_enforce' \
            --recommendation 'Enable "Require password after screen saver begins" in System Settings > Lock Screen, or via MDM: set com.apple.screensaver askForPassword=1.'
    fi
}

check_screensaver_grace_period() {
    if [[ -z "$CONSOLE_USER" ]]; then
        add_audit_result --category 'Screen Lock & Physical Access' --control 'Screensaver Password Grace Period' \
            --status WARN --severity Low --current 'No console user detected' \
            --recommended '<= 5 seconds' \
            --cis-macos 'CIS-macOS 2.10.2' --mscp 'os_screensaver_askforpassword_delay_enforce' \
            --recommendation 'Re-run interactively at a console login session to evaluate the screensaver grace period.'
        return
    fi
    local value
    value=$(defaults_read_as_user_safe 'com.apple.screensaver' 'askForPasswordDelay' '300')

    if [[ "$value" -le 5 ]]; then
        add_audit_result --category 'Screen Lock & Physical Access' --control 'Screensaver Password Grace Period' \
            --status PASS --severity Medium --current "askForPasswordDelay=${value}s" --recommended '<= 5 seconds' \
            --cis 'CIS 4.2' --nist 'AC-11' --cis-macos 'CIS-macOS 2.10.2' --mscp 'os_screensaver_askforpassword_delay_enforce' \
            --recommendation 'No action required.'
    else
        add_audit_result --category 'Screen Lock & Physical Access' --control 'Screensaver Password Grace Period' \
            --status WARN --severity Medium --current "askForPasswordDelay=${value}s" --recommended '<= 5 seconds' \
            --cis 'CIS 4.2' --nist 'AC-11' --cis-macos 'CIS-macOS 2.10.2' --mscp 'os_screensaver_askforpassword_delay_enforce' \
            --recommendation 'Reduce the screen lock grace period to 5 seconds or less in System Settings > Lock Screen, or via MDM: set com.apple.screensaver askForPasswordDelay=0.'
    fi
}

check_auto_login_disabled() {
    local value
    value=$(defaults_read_safe '/Library/Preferences/com.apple.loginwindow' 'autoLoginUser' '')

    if [[ -z "$value" ]]; then
        add_audit_result --category 'Screen Lock & Physical Access' --control 'Automatic Login Disabled' \
            --status PASS --severity Critical --current 'No autoLoginUser configured' --recommended 'No autoLoginUser configured' \
            --cis 'CIS 4.2' --nist 'AC-11, IA-2' --mitre 'T1078 (Valid Accounts)' --iso27001 'A.8.1' --nis2 'Art.21(2)(i)' \
            --cis-macos 'CIS-macOS 2.10.3' --mscp 'os_autologin_disable' \
            --recommendation 'No action required.'
    else
        add_audit_result --category 'Screen Lock & Physical Access' --control 'Automatic Login Disabled' \
            --status FAIL --severity Critical --current "autoLoginUser=$value" --recommended 'No autoLoginUser configured' \
            --cis 'CIS 4.2' --nist 'AC-11, IA-2' --mitre 'T1078 (Valid Accounts)' --iso27001 'A.8.1' --nis2 'Art.21(2)(i)' \
            --cis-macos 'CIS-macOS 2.10.3' --mscp 'os_autologin_disable' \
            --recommendation 'Disable automatic login in System Settings > Users & Groups > Login Options, or remove the key: sudo defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser.'
    fi
}

check_login_window_hardening() {
    local show_full_name
    show_full_name=$(defaults_read_safe '/Library/Preferences/com.apple.loginwindow' 'SHOWFULLNAME' '0')

    if [[ "$show_full_name" == "1" ]]; then
        add_audit_result --category 'Screen Lock & Physical Access' --control 'Login Window Hardening' \
            --status PASS --severity Medium --current 'SHOWFULLNAME=1' \
            --recommended 'SHOWFULLNAME=1' \
            --cis 'CIS 5.1' --nist 'IA-2' --mitre 'T1087 (Account Discovery)' --iso27001 'A.8.2' \
            --nis2 'Art.21(2)(i)' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'No action required.'
    else
        add_audit_result --category 'Screen Lock & Physical Access' --control 'Login Window Hardening' \
            --status WARN --severity Medium --current "SHOWFULLNAME=$show_full_name" \
            --recommended 'SHOWFULLNAME=1' \
            --cis 'CIS 5.1' --nist 'IA-2' --mitre 'T1087 (Account Discovery)' --iso27001 'A.8.2' \
            --nis2 'Art.21(2)(i)' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'Require a name-and-password login prompt instead of showing the account list: System Settings > Lock Screen, or "sudo defaults write /Library/Preferences/com.apple.loginwindow SHOWFULLNAME -bool true" — the account list reveals valid local usernames to anyone at the console.'
    fi
}

# --- CIS Apple macOS 26 Tahoe v1.0.0 sections 2.7.1, 2.11.1, 2.11.3, 2.11.5, 5.8 ---

check_screen_saver_corners_secure() {
    # Hot-corner action 6 = "Disable Screen Saver". CIS audits the
    # profile payload; the console user's own Dock prefs are checked
    # too, since a user-set corner defeats the lock just the same.
    local corner value
    local -a offending
    if load_config_profile_dump; then
        for corner in tl tr bl br; do
            value=$(config_profile_value "wvous-$corner-corner") && [[ "$value" == "6" ]] \
                && offending+=("wvous-$corner-corner = 6 (configuration profile)")
        done
    fi
    for corner in tl tr bl br; do
        value=$(defaults_read_as_user_safe com.apple.dock "wvous-$corner-corner" '')
        [[ "$value" == "6" ]] && offending+=("wvous-$corner-corner = 6 (${CONSOLE_USER:-console user} Dock prefs)")
    done

    local -a fw
    fw=(--recommended 'No hot corner set to Disable Screen Saver (action 6)' --cis 'CIS 4.3' --nist 'AC-11'
        --mitre 'T1200 (Hardware Additions)' --iso27001 'A.8.1' --nis2 'Art.21(2)(i)'
        --cis-macos 'CIS-macOS 2.7.1' --mscp 'system_settings_hot_corners_secure')
    if [[ ${#offending[@]} -eq 0 ]]; then
        add_audit_result --category 'Screen Lock & Physical Access' --control 'Screen Saver Hot Corners Secure' \
            --status PASS --severity Low --current 'No hot corner disables the screen saver' "${fw[@]}" \
            --recommendation 'No action required.'
    else
        add_audit_result --category 'Screen Lock & Physical Access' --control 'Screen Saver Hot Corners Secure' \
            --status FAIL --severity Low --current "${#offending[@]} hot corner(s) disable the screen saver" \
            --details "${(F)offending}" "${fw[@]}" \
            --recommendation 'Change the listed corner(s) in System Settings > Desktop & Dock > Hot Corners to any action other than "Disable Screen Saver".'
    fi
}

check_screensaver_idle_time() {
    evaluate_managed_pref --category 'Screen Lock & Physical Access' --control 'Screen Saver Inactivity <= 15 Minutes' \
        --severity Medium --suite com.apple.screensaver --key idleTime --min 1 --max 900 \
        --cis 'CIS 4.3' --nist 'AC-11' --mitre 'T1200 (Hardware Additions)' --iso27001 'A.8.1' --nis2 'Art.21(2)(i)' \
        --cis-macos 'CIS-macOS 2.11.1' --mscp 'system_settings_screensaver_timeout_enforce' \
        --recommendation 'Enforce a screen saver idle time of 900 seconds or less (and not 0 = never) via a Screensaver profile payload.'
}

check_login_window_custom_message() {
    local text rc
    text=$(managed_pref_read com.apple.loginwindow LoginwindowText)
    rc=$?
    local -a fw
    fw=(--recommended 'LoginwindowText set to the organization'"'"'s message' --cis 'CIS 4.1' --nist 'AC-8'
        --iso27001 'A.5.10' --nis2 'Art.21(2)(g)' --cis-macos 'CIS-macOS 2.11.3'
        --mscp 'system_settings_loginwindow_loginwindowtext_enable')
    if [[ $rc -eq 0 ]]; then
        add_audit_result --category 'Screen Lock & Physical Access' --control 'Login Window Custom Message' \
            --status PASS --severity Low --current "LoginwindowText: $text" "${fw[@]}" --recommendation 'No action required.'
    elif [[ $rc -eq 1 ]]; then
        add_audit_result --category 'Screen Lock & Physical Access' --control 'Login Window Custom Message' \
            --status WARN --severity Low --current 'No login window message configured' "${fw[@]}" \
            --recommendation 'Set a login window message: System Settings > Lock Screen > "Show message when locked", or "sudo defaults write /Library/Preferences/com.apple.loginwindow LoginwindowText '"'"'<text>'"'"'".'
    else
        add_audit_result --category 'Screen Lock & Physical Access' --control 'Login Window Custom Message' \
            --status WARN --severity Low --current 'Preference query failed' "${fw[@]}" \
            --recommendation 'Verify manually in System Settings > Lock Screen.'
    fi
}

check_login_window_password_hints_disabled() {
    evaluate_managed_pref --category 'Screen Lock & Physical Access' --control 'Show Password Hints Disabled' \
        --severity Medium --suite com.apple.loginwindow --key RetriesUntilHint --expect 0 \
        --cis 'CIS 4.1' --nist 'IA-6' --mitre 'T1110 (Brute Force)' --iso27001 'A.5.17' --nis2 'Art.21(2)(i)' \
        --cis-macos 'CIS-macOS 2.11.5' --mscp 'system_settings_password_hints_disable' \
        --recommendation 'Set RetriesUntilHint to 0: "sudo defaults write /Library/Preferences/com.apple.loginwindow RetriesUntilHint -int 0" (on Tahoe, 0 is the only value that hides the hint icon).'
}

_policy_banner_check() {
    local security_dir="$1"
    local -a banners
    banners=("$security_dir"/PolicyBanner.(txt|rtf|rtfd)(N))
    local -a fw
    fw=(--recommended 'PolicyBanner.txt/.rtf/.rtfd present and world-readable' --cis 'CIS 4.1' --nist 'AC-8'
        --iso27001 'A.5.10' --nis2 'Art.21(2)(g)' --cis-macos 'CIS-macOS 5.8' --mscp 'os_policy_banner_loginwindow_enforce')

    if [[ ${#banners[@]} -eq 0 ]]; then
        add_audit_result --category 'Screen Lock & Physical Access' --control 'Login Window Policy Banner' \
            --status FAIL --severity Low --current "No PolicyBanner file in $security_dir" "${fw[@]}" \
            --recommendation "Create $security_dir/PolicyBanner.txt (or .rtf) with the organization's acceptable-use notice, mode 644."
        return 0
    fi

    local f mode
    local -a unreadable
    for f in "${banners[@]}"; do
        mode=$(stat -f '%A' "$f" 2>/dev/null)
        # Last octal digit = "other" permissions; the login window can't
        # display a banner that isn't world-readable.
        (( ${mode: -1} & 4 )) || unreadable+=("$f ($mode)")
    done
    if [[ ${#unreadable[@]} -eq 0 ]]; then
        add_audit_result --category 'Screen Lock & Physical Access' --control 'Login Window Policy Banner' \
            --status PASS --severity Low --current "${banners[*]:t}" "${fw[@]}" --recommendation 'No action required.'
    else
        add_audit_result --category 'Screen Lock & Physical Access' --control 'Login Window Policy Banner' \
            --status FAIL --severity Low --current 'Policy banner exists but is not world-readable, so it will not display' \
            --details "${(F)unreadable}" "${fw[@]}" \
            --recommendation 'Make the banner readable: "sudo chmod o+r /Library/Security/PolicyBanner.*".'
    fi
}

check_login_window_policy_banner() {
    _policy_banner_check /Library/Security
}

# ---- 29-removable-media.zsh ----
#
# Domain 20: Removable Media & Peripheral Control

check_usb_restriction_profile_presence() {
    write_section_banner 'Removable Media & Peripheral Control - USB Restriction Profile Presence'
    run_root profiles list -type configuration

    local lower="${ROOT_CMD_OUTPUT:l}"
    if [[ "$lower" == *"usbrestrictedmode"* ]]; then
        add_audit_result --category 'Removable Media & Peripheral Control' --control 'USB Restriction Profile Presence' \
            --status INFO --severity Informational \
            --current 'A configuration profile referencing USB restricted mode is installed' \
            --recommended 'N/A' \
            --cis 'CIS 4.8' --nist 'MP-7' --iso27001 'A.7.10' --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 2.6' --mscp 'N/A' \
            --recommendation 'Informational only.'
    else
        add_audit_result --category 'Removable Media & Peripheral Control' --control 'USB Restriction Profile Presence' \
            --status WARN --severity Medium \
            --current 'No configuration profile appears to manage USB restricted mode' \
            --recommended 'A configuration profile referencing USB restricted mode is installed' \
            --cis 'CIS 4.8' --nist 'MP-7' --iso27001 'A.7.10' --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 2.6' --mscp 'N/A' \
            --recommendation 'This is a best-effort text match against installed profile identifiers, not full profile-payload inspection — confirm manually via MDM console if USB device control is required by policy.'
    fi
}

check_thunderbolt_security_level() {
    if is_apple_silicon; then
        add_audit_result --category 'Removable Media & Peripheral Control' --control 'Thunderbolt Security Level' \
            --status INFO --severity Informational \
            --current 'Not applicable — Apple Silicon Mac (DMA protection is enforced independently of the legacy Thunderbolt security-level setting)' \
            --recommended 'N/A' \
            --cis 'CIS 4.8' --nist 'SC-7' --iso27001 'A.7.10' --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 2.6' --mscp 'N/A' \
            --recommendation 'No action required.'
        return
    fi

    run_root system_profiler SPThunderboltDataType
    local line
    line=$(print -r -- "$ROOT_CMD_OUTPUT" | grep -i 'Security Level' | head -1)

    if [[ -z "$line" ]]; then
        add_audit_result --category 'Removable Media & Peripheral Control' --control 'Thunderbolt Security Level' \
            --status INFO --severity Informational \
            --current 'No Thunderbolt controller detected or unable to query' \
            --recommended 'N/A' --cis-macos 'CIS-macOS 2.6' --mscp 'N/A' \
            --recommendation 'Informational only.'
        return
    fi

    if [[ "$line" == *"No Security"* || "$line" == *"Legacy"* ]]; then
        add_audit_result --category 'Removable Media & Peripheral Control' --control 'Thunderbolt Security Level' \
            --status FAIL --severity High --current "$line" \
            --recommended 'Security Level: User Authorization (or stricter)' \
            --cis 'CIS 4.8' --nist 'SC-7' --mitre 'T1200 (Hardware Additions)' --iso27001 'A.7.10' \
            --nis2 'Art.21(2)(d)' --nsa 'NSA/CISA DMA Protection Guidance' --cis-macos 'CIS-macOS 2.6' --mscp 'N/A' \
            --recommendation 'Set Thunderbolt security to "User Authorization" or stricter via the Thunderbolt pane (Intel Macs) or firmware boot security settings.'
    elif [[ "$line" == *"User Authorization"* ]]; then
        add_audit_result --category 'Removable Media & Peripheral Control' --control 'Thunderbolt Security Level' \
            --status PASS --severity High --current "$line" \
            --recommended 'Security Level: User Authorization (or stricter)' \
            --cis 'CIS 4.8' --nist 'SC-7' --mitre 'T1200 (Hardware Additions)' --iso27001 'A.7.10' \
            --nis2 'Art.21(2)(d)' --nsa 'NSA/CISA DMA Protection Guidance' --cis-macos 'CIS-macOS 2.6' --mscp 'N/A' \
            --recommendation 'No action required.'
    else
        # Fault isolation: an unrecognized security-level value must never
        # be silently reported identically to a verified-clean PASS above.
        add_audit_result --category 'Removable Media & Peripheral Control' --control 'Thunderbolt Security Level' \
            --status WARN --severity Low --current "Unrecognized security level: $line" \
            --recommended 'Security Level: User Authorization (or stricter)' \
            --cis-macos 'CIS-macOS 2.6' --mscp 'N/A' \
            --recommendation 'Unable to classify the reported Thunderbolt security level; verify manually with "system_profiler SPThunderboltDataType".'
    fi
}

# ---- 30-wireless-network.zsh ----
#
# Domain 21: Wireless & Network Interface Security

check_wifi_current_network_security() {
    write_section_banner 'Wireless & Network Interface Security - Wi-Fi Current Network Security'
    run_root system_profiler SPAirPortDataType

    local block security_line
    block=$(print -r -- "$ROOT_CMD_OUTPUT" | awk '/Current Network Information:/{flag=1} flag{print}')
    security_line=$(print -r -- "$block" | grep 'Security:' | head -1)
    security_line="${security_line##*Security:}"
    security_line="${security_line## }"

    if [[ -z "$security_line" ]]; then
        add_audit_result --category 'Wireless & Network Interface Security' --control 'Wi-Fi Current Network Security' \
            --status INFO --severity Informational --current 'Not currently associated with a Wi-Fi network' \
            --recommended 'N/A' --cis-macos 'CIS-macOS 2.9' --mscp 'N/A' \
            --recommendation 'Informational only.'
    elif [[ "$security_line" == *"WEP"* || "$security_line" == *"None"* || "$security_line" == *"Open"* ]]; then
        add_audit_result --category 'Wireless & Network Interface Security' --control 'Wi-Fi Current Network Security' \
            --status WARN --severity Medium --current "$security_line" \
            --recommended 'WPA2 or WPA3' \
            --cis 'CIS 12.6' --nist 'AC-18' --mitre 'T1040 (Network Sniffing)' --iso27001 'A.8.20' \
            --nis2 'Art.21(2)(h)' --nsa 'NSA/CISA Wireless Security Guidance' --cis-macos 'CIS-macOS 2.9' --mscp 'N/A' \
            --recommendation 'Reconfigure or avoid this network — WEP and open networks provide no meaningful confidentiality.'
    elif [[ "$security_line" == *"WPA2"* || "$security_line" == *"WPA3"* ]]; then
        add_audit_result --category 'Wireless & Network Interface Security' --control 'Wi-Fi Current Network Security' \
            --status PASS --severity Medium --current "$security_line" \
            --recommended 'WPA2 or WPA3' \
            --cis 'CIS 12.6' --nist 'AC-18' --mitre 'T1040 (Network Sniffing)' --iso27001 'A.8.20' \
            --nis2 'Art.21(2)(h)' --nsa 'NSA/CISA Wireless Security Guidance' --cis-macos 'CIS-macOS 2.9' --mscp 'N/A' \
            --recommendation 'No action required.'
    else
        add_audit_result --category 'Wireless & Network Interface Security' --control 'Wi-Fi Current Network Security' \
            --status WARN --severity Low --current "Unrecognized security value: $security_line" \
            --recommended 'WPA2 or WPA3' \
            --cis-macos 'CIS-macOS 2.9' --mscp 'N/A' \
            --recommendation 'Unable to classify the reported Wi-Fi security type; verify manually with "system_profiler SPAirPortDataType".'
    fi
}

check_bluetooth_power_state() {
    local power_state
    power_state=$(defaults_read_safe '/Library/Preferences/com.apple.Bluetooth' 'ControllerPowerState' '0')

    # Always INFO: on/off is a usability choice, not a finding.
    if [[ "$power_state" == "1" ]]; then
        add_audit_result --category 'Wireless & Network Interface Security' --control 'Bluetooth Power State' \
            --status INFO --severity Informational --current 'Bluetooth powered on' \
            --recommended 'N/A' --cis-macos 'CIS-macOS 2.9' --mscp 'N/A' \
            --recommendation 'Informational only.'
    else
        add_audit_result --category 'Wireless & Network Interface Security' --control 'Bluetooth Power State' \
            --status INFO --severity Informational --current 'Bluetooth powered off' \
            --recommended 'N/A' --cis-macos 'CIS-macOS 2.9' --mscp 'N/A' \
            --recommendation 'Informational only.'
    fi
}

check_airdrop_discovery_scope() {
    local mode
    mode=$(defaults_read_as_user_safe 'com.apple.sharingd' 'DiscoverableMode' 'Contacts Only')

    if [[ "$mode" == "Everyone" ]]; then
        add_audit_result --category 'Wireless & Network Interface Security' --control 'AirDrop Discovery Scope' \
            --status WARN --severity Medium --current "DiscoverableMode: $mode" \
            --recommended 'Contacts Only or No One' \
            --cis 'CIS 4.8' --nist 'AC-18' --mitre 'T1092 (Communication Through Removable Media)' --iso27001 'A.8.20' \
            --nis2 'Art.21(2)(h)' --cis-macos 'CIS-macOS 2.9' --mscp 'N/A' \
            --recommendation 'Set AirDrop to "Contacts Only" or "No One" via Control Center/System Settings unless open discovery is deliberately needed.'
    else
        add_audit_result --category 'Wireless & Network Interface Security' --control 'AirDrop Discovery Scope' \
            --status PASS --severity Medium --current "DiscoverableMode: $mode" \
            --recommended 'Contacts Only or No One' \
            --cis 'CIS 4.8' --nist 'AC-18' --mitre 'T1092 (Communication Through Removable Media)' --iso27001 'A.8.20' \
            --nis2 'Art.21(2)(h)' --cis-macos 'CIS-macOS 2.9' --mscp 'N/A' \
            --recommendation 'No action required.'
    fi
}

check_network_interface_inventory() {
    run_root networksetup -listallhardwareports

    local -a ports
    ports=("${(@f)$(print -r -- "$ROOT_CMD_OUTPUT" | grep '^Hardware Port:')}")

    local -a names=()
    local p
    for p in "${ports[@]}"; do
        # Zero grep matches still yields a one-element array holding an
        # empty string (command substitution of nothing, split on
        # newlines), not zero elements — without this guard, a query
        # returning no ports at all would count as "1 interface(s)".
        [[ -z "$p" ]] && continue
        names+=("${p#Hardware Port: }")
    done
    local count=${#names[@]}
    local joined
    joined=$(printf '%s\n' "${names[@]}")

    # Always INFO: this is inventory, not a judgement.
    add_audit_result --category 'Wireless & Network Interface Security' --control 'Network Interface Inventory' \
        --status INFO --severity Informational --current "$count interface(s)" --details "$joined" \
        --recommended 'N/A' --cis-macos 'CIS-macOS 2.9' --mscp 'N/A' \
        --recommendation 'Informational only.'
}

# ---- 31-icloud-sync.zsh ----
#
# Domain 22: iCloud & Cloud Sync Surface

check_icloud_keychain_sync_indicator() {
    write_section_banner 'iCloud & Cloud Sync Surface - iCloud Keychain Sync Indicator'
    local accounts_dump
    accounts_dump=$(defaults_read_as_user_safe 'MobileMeAccounts' 'Accounts' '')

    # Always INFO: this is acknowledged best-effort text matching against
    # an internal plist structure, not a pass/fail judgement.
    if [[ "$accounts_dump" == *"Keychain"* ]]; then
        add_audit_result --category 'iCloud & Cloud Sync Surface' --control 'iCloud Keychain Sync Indicator' \
            --status INFO --severity Informational \
            --current 'An iCloud account with Keychain sync appears to be configured' \
            --recommended 'N/A' --cis-macos 'CIS-macOS 2.11' --mscp 'N/A' \
            --recommendation 'Informational only.'
    else
        add_audit_result --category 'iCloud & Cloud Sync Surface' --control 'iCloud Keychain Sync Indicator' \
            --status INFO --severity Informational \
            --current 'No iCloud Keychain sync indicator found (best-effort parse of an internal plist structure — verify manually in System Settings > Apple ID > iCloud if certainty is required)' \
            --recommended 'N/A' --cis-macos 'CIS-macOS 2.11' --mscp 'N/A' \
            --recommendation 'Informational only.'
    fi
}

check_activation_lock_status() {
    run_root system_profiler SPHardwareDataType

    local line
    line=$(print -r -- "$ROOT_CMD_OUTPUT" | grep 'Activation Lock Status' | head -1)

    if [[ "$line" == *"Enabled"* ]]; then
        add_audit_result --category 'iCloud & Cloud Sync Surface' --control 'Activation Lock Status' \
            --status PASS --severity Medium --current "$line" \
            --recommended 'Activation Lock Status: Enabled' \
            --cis 'CIS 4.8' --nist 'PE-20' --iso27001 'A.7.10' --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 2.11' --mscp 'N/A' \
            --recommendation 'No action required — this is a theft-deterrence control.'
    elif [[ "$line" == *"Disabled"* ]]; then
        add_audit_result --category 'iCloud & Cloud Sync Surface' --control 'Activation Lock Status' \
            --status WARN --severity Medium --current "$line" \
            --recommended 'Activation Lock Status: Enabled' \
            --cis 'CIS 4.8' --nist 'PE-20' --iso27001 'A.7.10' --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 2.11' --mscp 'N/A' \
            --recommendation 'Consider enabling Find My Mac (System Settings > Apple ID > iCloud > Find My Mac) so Activation Lock engages.'
    else
        add_audit_result --category 'iCloud & Cloud Sync Surface' --control 'Activation Lock Status' \
            --status INFO --severity Informational --current 'Activation Lock Status not reported (older hardware without the feature)' \
            --recommended 'N/A' --cis-macos 'CIS-macOS 2.11' --mscp 'N/A' \
            --recommendation 'Informational only.'
    fi
}

# Reports whether iCloud Drive's local sync folder exists under the given
# home directory. Directly testable against a scratch home.
_icloud_drive_present() {
    local home="$1"
    run_as_user test -d "$home/Library/Mobile Documents/com~apple~CloudDocs"

    # Always INFO: iCloud Drive use is a legitimate business choice, not a
    # finding.
    if [[ $RUN_AS_USER_STATUS -eq 0 ]]; then
        add_audit_result --category 'iCloud & Cloud Sync Surface' --control 'iCloud Drive Sync Indicator' \
            --status INFO --severity Informational --current 'iCloud Drive local sync folder present' \
            --recommended 'N/A' --cis-macos 'CIS-macOS 2.11' --mscp 'N/A' \
            --recommendation 'Informational only.'
    else
        add_audit_result --category 'iCloud & Cloud Sync Surface' --control 'iCloud Drive Sync Indicator' \
            --status INFO --severity Informational --current 'iCloud Drive local sync folder absent' \
            --recommended 'N/A' --cis-macos 'CIS-macOS 2.11' --mscp 'N/A' \
            --recommendation 'Informational only.'
    fi
}

check_icloud_drive_sync_indicator() {
    if [[ -z "$CONSOLE_USER" ]]; then
        add_audit_result --category 'iCloud & Cloud Sync Surface' --control 'iCloud Drive Sync Indicator' \
            --status WARN --severity Low --current 'No console user detected' \
            --recommended 'N/A' --cis-macos 'CIS-macOS 2.11' --mscp 'N/A' \
            --recommendation 'Re-run interactively at a console login session to evaluate iCloud Drive sync status.'
        return
    fi
    _icloud_drive_present "$(eval echo ~$CONSOLE_USER)"
}

# --- CIS Apple macOS 26 Tahoe v1.0.0 section 2.1.1.3 ---

check_icloud_desktop_documents_sync_disabled() {
    evaluate_managed_pref --category 'iCloud & Cloud Sync Surface' --control 'iCloud Desktop & Documents Sync Disabled' \
        --severity Low --suite com.apple.applicationaccess --key allowCloudDesktopAndDocuments --expect 0 \
        --cis 'CIS 4.1, 4.8, 15.3' --nist 'AC-20, SC-7' --mitre 'T1567.002 (Exfiltration to Cloud Storage)' \
        --iso27001 'A.5.14' --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 2.1.1.3' --mscp 'N/A' \
        --recommendation 'Deploy a Restrictions profile with allowCloudDesktopAndDocuments=false so Desktop and Documents are not synced to a personal iCloud account.'
}

# ---- 32-browser-hardening.zsh ----
#
# Domain 23: Browser & Application Hardening

check_safari_auto_open_safe_downloads() {
    write_section_banner 'Browser & Application Hardening - Safari Auto-Open Safe Downloads'
    local auto_open
    auto_open=$(defaults_read_as_user_safe 'com.apple.Safari' 'AutoOpenSafeDownloads' '0')

    if [[ "$auto_open" == "1" ]]; then
        add_audit_result --category 'Browser & Application Hardening' --control 'Safari Auto-Open Safe Downloads' \
            --status FAIL --severity Medium --current 'AutoOpenSafeDownloads=1' \
            --recommended 'AutoOpenSafeDownloads=0' \
            --cis 'CIS 9.2' --nist 'CM-7' --mitre 'T1204.002 (Malicious File)' --iso27001 'A.8.19' \
            --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 2.13' --mscp 'N/A' \
            --recommendation 'Disable "Open safe files after downloading" in Safari > Settings > General — auto-opening downloaded archives/disk images is a long-standing abuse vector.'
    else
        add_audit_result --category 'Browser & Application Hardening' --control 'Safari Auto-Open Safe Downloads' \
            --status PASS --severity Medium --current "AutoOpenSafeDownloads=$auto_open" \
            --recommended 'AutoOpenSafeDownloads=0' \
            --cis 'CIS 9.2' --nist 'CM-7' --mitre 'T1204.002 (Malicious File)' --iso27001 'A.8.19' \
            --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 2.13' --mscp 'N/A' \
            --recommendation 'No action required.'
    fi
}

check_safari_developer_menu_note() {
    local develop_menu
    develop_menu=$(defaults_read_as_user_safe 'com.apple.Safari' 'IncludeDevelopMenu' '0')

    # Always INFO: developer-menu visibility is not inherently a security
    # issue.
    if [[ "$develop_menu" == "1" ]]; then
        add_audit_result --category 'Browser & Application Hardening' --control 'Safari Developer Menu' \
            --status INFO --severity Informational --current 'Develop menu on' \
            --recommended 'N/A' --cis-macos 'CIS-macOS 2.13' --mscp 'N/A' \
            --recommendation 'Informational only.'
    else
        add_audit_result --category 'Browser & Application Hardening' --control 'Safari Developer Menu' \
            --status INFO --severity Informational --current 'Develop menu off' \
            --recommended 'N/A' --cis-macos 'CIS-macOS 2.13' --mscp 'N/A' \
            --recommendation 'Informational only.'
    fi
}

check_safari_fraudulent_site_warning() {
    local warn_setting
    warn_setting=$(defaults_read_as_user_safe 'com.apple.Safari' 'WarnAboutFraudulentWebsites' '1')

    if [[ "$warn_setting" == "0" ]]; then
        add_audit_result --category 'Browser & Application Hardening' --control 'Safari Fraudulent Site Warning' \
            --status FAIL --severity Medium --current 'WarnAboutFraudulentWebsites=0' \
            --recommended 'WarnAboutFraudulentWebsites=1' \
            --cis 'CIS 9.2' --nist 'SC-7' --mitre 'T1566 (Phishing)' --iso27001 'A.8.23' \
            --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 2.13' --mscp 'N/A' \
            --recommendation 're-enable "Warn when visiting a fraudulent website" in Safari > Settings > Security.'
    else
        add_audit_result --category 'Browser & Application Hardening' --control 'Safari Fraudulent Site Warning' \
            --status PASS --severity Medium --current "WarnAboutFraudulentWebsites=$warn_setting" \
            --recommended 'WarnAboutFraudulentWebsites=1' \
            --cis 'CIS 9.2' --nist 'SC-7' --mitre 'T1566 (Phishing)' --iso27001 'A.8.23' \
            --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 2.13' --mscp 'N/A' \
            --recommendation 'No action required.'
    fi
}

# --- CIS Apple macOS 26 Tahoe v1.0.0 sections 6.3.4, 6.3.6, 6.3.7, 6.3.10, 6.4.1 ---
# CIS audits these Safari settings only via an installed configuration
# profile (system_profiler SPConfigurationProfileDataType).

check_safari_cross_site_tracking_prevention() {
    evaluate_profile_payload --category 'Browser & Application Hardening' --control 'Safari Prevent Cross-Site Tracking' \
        --severity Low --pair 'BlockStoragePolicy=2' --pair 'WebKitPreferences.storageBlockingPolicy=1' \
        --pair 'WebKitStorageBlockingPolicy=1' \
        --cis 'CIS 9.1' --nist 'SC-7, SI-12' --iso27001 'A.8.23' --nis2 'Art.21(2)(d)' \
        --cis-macos 'CIS-macOS 6.3.4' --mscp 'os_safari_prevent_cross-site_tracking_enable' \
        --recommendation 'Deploy a com.apple.Safari profile payload with BlockStoragePolicy=2, WebKitPreferences.storageBlockingPolicy=1 and WebKitStorageBlockingPolicy=1.'
}

check_safari_advertising_privacy_protection() {
    evaluate_profile_payload --category 'Browser & Application Hardening' --control 'Safari Advertising Privacy Protection' \
        --severity Low --pair 'WebKitPreferences.privateClickMeasurementEnabled=1' \
        --cis 'CIS 9.1' --nist 'SI-12' --iso27001 'A.8.23' --nis2 'Art.21(2)(d)' \
        --cis-macos 'CIS-macOS 6.3.6' --mscp 'os_safari_advertising_privacy_protection_enable' \
        --recommendation 'Deploy a com.apple.Safari profile payload with WebKitPreferences.privateClickMeasurementEnabled=true.'
}

check_safari_show_full_website_address() {
    evaluate_profile_payload --category 'Browser & Application Hardening' --control 'Safari Show Full Website Address' \
        --severity Low --pair 'ShowFullURLInSmartSearchField=1' \
        --cis 'CIS 9.1' --nist 'SI-3' --mitre 'T1566.002 (Spearphishing Link)' --iso27001 'A.8.23' --nis2 'Art.21(2)(d)' \
        --cis-macos 'CIS-macOS 6.3.7' --mscp 'os_safari_show_full_website_address_enable' \
        --recommendation 'Deploy a com.apple.Safari profile payload with ShowFullURLInSmartSearchField=true so users see the real domain they are on.'
}

check_safari_show_status_bar() {
    evaluate_profile_payload --category 'Browser & Application Hardening' --control 'Safari Show Status Bar' \
        --severity Low --pair 'ShowOverlayStatusBar=1' \
        --cis 'CIS 9.1' --nist 'SI-3' --mitre 'T1566.002 (Spearphishing Link)' --iso27001 'A.8.23' --nis2 'Art.21(2)(d)' \
        --cis-macos 'CIS-macOS 6.3.10' --mscp 'os_safari_show_status_bar_enabled' \
        --recommendation 'Deploy a com.apple.Safari profile payload with ShowOverlayStatusBar=true so link targets are visible on hover.'
}

check_terminal_secure_keyboard_entry() {
    evaluate_managed_pref --category 'Browser & Application Hardening' --control 'Terminal Secure Keyboard Entry' \
        --severity Medium --suite com.apple.Terminal --key SecureKeyboardEntry --expect 1 \
        --cis 'CIS 4.8' --nist 'SC-3' --mitre 'T1056.001 (Keylogging)' --iso27001 'A.8.7' --nis2 'Art.21(2)(d)' \
        --cis-macos 'CIS-macOS 6.4.1' --mscp 'os_terminal_secure_keyboard_enable' \
        --recommendation 'Enforce Terminal Secure Keyboard Entry (com.apple.Terminal SecureKeyboardEntry=true) via profile so other processes cannot read keystrokes typed into Terminal, including sudo passwords.'
}

# ---- 33-ransomware-resilience.zsh ----
#
# Domain 24: Ransomware Resilience & Recovery

check_time_machine_configured_and_recent() {
    write_section_banner 'Ransomware Resilience & Recovery - Time Machine Configured & Recent'
    run_root tmutil destinationinfo

    if [[ $ROOT_CMD_STATUS -ne 0 || "$ROOT_CMD_OUTPUT" == *"No destinations configured"* ]]; then
        add_audit_result --category 'Ransomware Resilience & Recovery' --control 'Time Machine Configured & Recent' \
            --status FAIL --severity High --current 'No Time Machine destination configured' \
            --recommended 'A Time Machine destination is configured, backed up within 7 days' \
            --cis 'CIS 11.2' --nist 'CP-9' --mitre 'T1490 (Inhibit System Recovery)' --iso27001 'A.8.13' \
            --nis2 'Art.21(2)(c)' --nsa 'NSA/CISA Ransomware Resilience Guidance' --cis-macos 'CIS-macOS 1.5' --mscp 'N/A' \
            --recommendation 'Configure a Time Machine destination (System Settings > General > Time Machine) as baseline ransomware/data-loss recovery.'
        return
    fi

    run_root tmutil latestbackup
    local date_token
    date_token=$(print -r -- "$ROOT_CMD_OUTPUT" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{6}' | tail -1)
    local date_only="${date_token%-*}"

    local epoch=""
    if [[ $ROOT_CMD_STATUS -eq 0 && -n "$date_only" ]]; then
        epoch=$(date -j -f "%Y-%m-%d" "$date_only" +%s 2>/dev/null)
    fi

    if [[ -z "$epoch" ]]; then
        add_audit_result --category 'Ransomware Resilience & Recovery' --control 'Time Machine Configured & Recent' \
            --status WARN --severity Medium --current 'Unable to determine latest backup date' \
            --recommended 'A Time Machine destination is configured, backed up within 7 days' \
            --cis 'CIS 11.2' --nist 'CP-9' --mitre 'T1490 (Inhibit System Recovery)' --iso27001 'A.8.13' \
            --nis2 'Art.21(2)(c)' --nsa 'NSA/CISA Ransomware Resilience Guidance' --cis-macos 'CIS-macOS 1.5' --mscp 'N/A' \
            --recommendation 'Unable to parse the latest backup date; verify manually with "tmutil latestbackup".'
        return
    fi

    local now days_since
    now=$(date +%s)
    days_since=$(( (now - epoch) / 86400 ))

    if (( days_since <= 7 )); then
        add_audit_result --category 'Ransomware Resilience & Recovery' --control 'Time Machine Configured & Recent' \
            --status PASS --severity High --current "Latest backup: $date_only ($days_since day(s) ago)" \
            --recommended 'A Time Machine destination is configured, backed up within 7 days' \
            --cis 'CIS 11.2' --nist 'CP-9' --mitre 'T1490 (Inhibit System Recovery)' --iso27001 'A.8.13' \
            --nis2 'Art.21(2)(c)' --nsa 'NSA/CISA Ransomware Resilience Guidance' --cis-macos 'CIS-macOS 1.5' --mscp 'N/A' \
            --recommendation 'No action required.'
    else
        add_audit_result --category 'Ransomware Resilience & Recovery' --control 'Time Machine Configured & Recent' \
            --status WARN --severity Medium --current "$days_since day(s) since last backup" \
            --recommended 'A Time Machine destination is configured, backed up within 7 days' \
            --cis 'CIS 11.2' --nist 'CP-9' --mitre 'T1490 (Inhibit System Recovery)' --iso27001 'A.8.13' \
            --nis2 'Art.21(2)(c)' --nsa 'NSA/CISA Ransomware Resilience Guidance' --cis-macos 'CIS-macOS 1.5' --mscp 'N/A' \
            --recommendation 'Investigate why backups have stalled.'
    fi
}

# CIS 2.3.4.2. Replaces the former always-INFO "encryption note": CIS
# documents a CLI signal — each destination's LastKnownEncryptionState in
# /Library/Preferences/com.apple.TimeMachine.plist — so this now reports
# a real result. Parameterized on the plist path for tests.
_time_machine_encryption_check() {
    local tm_plist="$1"
    local -a fw
    fw=(--recommended 'Every Time Machine destination Encrypted' --cis 'CIS 3.6, 3.11, 11.3' --nist 'SC-28, CP-9(8)'
        --mitre 'T1005 (Data from Local System)' --iso27001 'A.8.24' --nis2 'Art.21(2)(h)'
        --cis-macos 'CIS-macOS 2.3.4.2' --mscp 'system_settings_time_machine_encrypted_configure')

    run_root defaults read "$tm_plist" Destinations
    if [[ $ROOT_CMD_STATUS -ne 0 || "$ROOT_CMD_OUTPUT" != *DestinationID* ]]; then
        add_audit_result --category 'Ransomware Resilience & Recovery' --control 'Time Machine Backup Encryption' \
            --status INFO --severity Informational --current 'No Time Machine destination configured' "${fw[@]}" \
            --recommendation 'Not applicable until a Time Machine destination is configured; see "Time Machine Configured & Recent".'
        return 0
    fi

    local total encrypted not_encrypted
    total=$(print -r -- "$ROOT_CMD_OUTPUT" | grep -c 'DestinationID')
    not_encrypted=$(print -r -- "$ROOT_CMD_OUTPUT" | grep -c 'LastKnownEncryptionState = NotEncrypted')
    encrypted=$(print -r -- "$ROOT_CMD_OUTPUT" | grep -c 'LastKnownEncryptionState = Encrypted')

    if (( not_encrypted > 0 )); then
        add_audit_result --category 'Ransomware Resilience & Recovery' --control 'Time Machine Backup Encryption' \
            --status FAIL --severity High --current "$not_encrypted of $total destination(s) NotEncrypted" "${fw[@]}" \
            --recommendation 'Re-add each unencrypted destination with "Encrypt Backups" selected (System Settings > General > Time Machine); an unencrypted backup disk holds a readable copy of the whole FileVault-protected volume.'
    elif (( encrypted == total )); then
        add_audit_result --category 'Ransomware Resilience & Recovery' --control 'Time Machine Backup Encryption' \
            --status PASS --severity High --current "All $total destination(s) Encrypted" "${fw[@]}" \
            --recommendation 'No action required.'
    else
        add_audit_result --category 'Ransomware Resilience & Recovery' --control 'Time Machine Backup Encryption' \
            --status WARN --severity Medium --current "Encryption state unknown for $(( total - encrypted )) of $total destination(s)" "${fw[@]}" \
            --recommendation 'Confirm each destination shows "Encrypted" in System Settings > General > Time Machine (state is recorded after the first backup).'
    fi
}

check_time_machine_encryption() {
    _time_machine_encryption_check /Library/Preferences/com.apple.TimeMachine.plist
}

check_time_machine_auto_backup() {
    evaluate_managed_pref --category 'Ransomware Resilience & Recovery' --control 'Time Machine Automatic Backup' \
        --severity Low --suite com.apple.TimeMachine --key AutoBackup --expect 1 --unset-ok \
        --cis 'CIS 11.2' --nist 'CP-9' --mitre 'T1490 (Inhibit System Recovery)' --iso27001 'A.8.13' \
        --nis2 'Art.21(2)(c)' --cis-macos 'CIS-macOS 2.3.4.1' --mscp 'system_settings_time_machine_auto_backup_enable' \
        --recommendation 'Set Time Machine to back up automatically (System Settings > General > Time Machine > Options > Back up frequency), or enforce AutoBackup=true via profile.'
}

check_local_apfs_snapshots() {
    run_root tmutil listlocalsnapshots /

    local count
    count=$(print -r -- "$ROOT_CMD_OUTPUT" | grep -vc 'Snapshots for disk')

    # Always INFO: local snapshots provide fast local rollback but are not
    # a substitute for an off-device backup.
    add_audit_result --category 'Ransomware Resilience & Recovery' --control 'Local APFS Snapshots' \
        --status INFO --severity Informational --current "$count local snapshot(s) found" \
        --recommended 'N/A' --cis-macos 'CIS-macOS 1.5' --mscp 'N/A' \
        --recommendation 'Informational only. Local snapshots provide fast local rollback but are not a substitute for an off-device backup.'
}

# ---- 34-software-inventory.zsh ----
#
# Domain 25: Third-Party Software & Package Inventory

_homebrew_prefix() {
    if is_apple_silicon; then
        echo '/opt/homebrew'
    else
        echo '/usr/local'
    fi
}

# Bounded, top-level-only application inventory. Directly testable
# against a scratch dir with fake .app names.
_applications_inventory_check() {
    local dir="$1"
    run_root find "$dir" -maxdepth 1 -name '*.app'

    local -a apps names
    apps=("${(@f)ROOT_CMD_OUTPUT}")
    names=()
    local a
    for a in "${apps[@]}"; do
        [[ -z "$a" ]] && continue
        names+=("${a:t}")
    done

    local total=${#names[@]}
    local joined
    joined=$(printf '%s\n' "${names[@]}")

    # Always INFO: this is inventory, not a judgement. The full name list
    # lives in --details (hover tooltip) rather than inline — with up to
    # a few dozen apps, showing it inline would blow out the row.
    add_audit_result --category 'Third-Party Software & Package Inventory' --control 'Installed Applications Inventory' \
        --status INFO --severity Informational --current "$total application(s) installed" \
        --details "$joined" \
        --recommended 'N/A' --cis-macos 'CIS-macOS 1.6' --mscp 'N/A' \
        --recommendation 'Informational only.'
}

check_installed_applications_inventory() {
    write_section_banner 'Third-Party Software & Package Inventory - Installed Applications Inventory'
    _applications_inventory_check '/Applications'
}

# Directly testable with a scratch dir via chmod.
_homebrew_prefix_check() {
    local prefix="$1"

    if [[ ! -d "$prefix" ]]; then
        add_audit_result --category 'Third-Party Software & Package Inventory' --control 'Homebrew Prefix Permissions' \
            --status INFO --severity Informational --current 'Homebrew not installed' \
            --recommended 'N/A' --cis-macos 'CIS-macOS 1.6' --mscp 'N/A' \
            --recommendation 'Informational only.'
        return
    fi

    run_root stat -f '%Lp' "$prefix"
    if [[ $ROOT_CMD_STATUS -ne 0 ]]; then
        add_audit_result --category 'Third-Party Software & Package Inventory' --control 'Homebrew Prefix Permissions' \
            --status WARN --severity Low --current "stat query failed: $ROOT_CMD_OUTPUT" \
            --recommended 'No group/other write bit' --cis-macos 'CIS-macOS 1.6' --mscp 'N/A' \
            --recommendation "Unable to verify permissions for $prefix; check manually with \"stat -f '%Lp' $prefix\"."
        return
    fi

    local mode="$ROOT_CMD_OUTPUT"
    local last3="${mode: -3}"
    local group_digit="${last3:1:1}" other_digit="${last3:2:1}"

    if (( (group_digit & 2) != 0 || (other_digit & 2) != 0 )); then
        add_audit_result --category 'Third-Party Software & Package Inventory' --control 'Homebrew Prefix Permissions' \
            --status FAIL --severity High --current "$prefix mode $mode" \
            --recommended 'No group/other write bit' \
            --cis 'CIS 2.7' --nist 'CM-7, AC-6' --mitre 'T1574.007 (PATH Interception)' --iso27001 'A.8.19' \
            --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 1.6' --mscp 'N/A' \
            --recommendation "sudo chmod -R go-w $prefix — a writable Homebrew prefix lets any local user hijack the next brew invocation or any binary on \$PATH under that prefix."
    else
        add_audit_result --category 'Third-Party Software & Package Inventory' --control 'Homebrew Prefix Permissions' \
            --status PASS --severity High --current "$prefix mode $mode" \
            --recommended 'No group/other write bit' \
            --cis 'CIS 2.7' --nist 'CM-7, AC-6' --mitre 'T1574.007 (PATH Interception)' --iso27001 'A.8.19' \
            --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 1.6' --mscp 'N/A' \
            --recommendation 'No action required.'
    fi
}

check_homebrew_prefix_permissions() {
    _homebrew_prefix_check "$(_homebrew_prefix)"
}

# Best-effort count, not equivalent to "brew list" — kept dependency-free
# by never invoking brew itself.
_homebrew_package_inventory_check() {
    local prefix="$1"

    if [[ ! -d "$prefix" ]]; then
        add_audit_result --category 'Third-Party Software & Package Inventory' --control 'Homebrew Package Inventory' \
            --status INFO --severity Informational --current 'Homebrew not installed' \
            --recommended 'N/A' --cis-macos 'CIS-macOS 1.6' --mscp 'N/A' \
            --recommendation 'Informational only.'
        return
    fi

    if [[ ! -d "$prefix/Cellar" ]]; then
        add_audit_result --category 'Third-Party Software & Package Inventory' --control 'Homebrew Package Inventory' \
            --status INFO --severity Informational \
            --current "0 Homebrew formula directory(ies) found under Cellar (best-effort count, not equivalent to 'brew list')" \
            --recommended 'N/A' --cis-macos 'CIS-macOS 1.6' --mscp 'N/A' \
            --recommendation 'Informational only.'
        return
    fi

    run_root find "$prefix/Cellar" -maxdepth 1 -type d
    local -a dirs names=()
    dirs=("${(@f)ROOT_CMD_OUTPUT}")
    local d
    for d in "${dirs[@]}"; do
        [[ -z "$d" || "$d" == "$prefix/Cellar" ]] && continue
        names+=("${d:t}")
    done

    local joined
    joined=$(printf '%s\n' "${names[@]}")

    add_audit_result --category 'Third-Party Software & Package Inventory' --control 'Homebrew Package Inventory' \
        --status INFO --severity Informational \
        --current "${#names[@]} Homebrew formula directory(ies) found under Cellar (best-effort count, not equivalent to 'brew list')" \
        --details "$joined" \
        --recommended 'N/A' --cis-macos 'CIS-macOS 1.6' --mscp 'N/A' \
        --recommendation 'Informational only.'
}

check_homebrew_package_inventory() {
    _homebrew_package_inventory_check "$(_homebrew_prefix)"
}

# ---- 35-services-daemons.zsh ----
#
# Domain 26: System Services & Daemon Exposure

check_listening_ports_inventory() {
    write_section_banner 'System Services & Daemon Exposure - Listening Ports Inventory'
    run_root lsof -iTCP -sTCP:LISTEN -P -n

    local -a lines data_lines
    lines=("${(@f)ROOT_CMD_OUTPUT}")
    data_lines=("${lines[@]:1}")

    local count=0
    local -a ports=()
    local line
    for line in "${data_lines[@]}"; do
        [[ -z "$line" ]] && continue
        count=$((count + 1))
        local -a words
        words=(${=line})
        local addr_port="${words[-2]}"
        ports+=("${addr_port##*:}")
    done

    local -a distinct_ports
    distinct_ports=("${(@onu)ports}")
    local joined
    joined=$(printf '%s\n' "${distinct_ports[@]}")

    # Always INFO: an inventory, not a judgement — mirrors the original
    # tool's own informational-severity "Firewall Inbound Active Rules
    # Inventory" check.
    add_audit_result --category 'System Services & Daemon Exposure' --control 'Listening Ports Inventory' \
        --status INFO --severity Informational --current "$count listening port(s) found" --details "$joined" \
        --recommended 'N/A' \
        --cis 'CIS 12.4' --nist 'CA-9' --iso27001 'A.8.20' --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 5.7' --mscp 'N/A' \
        --recommendation 'Informational only.'
}

check_nonapple_running_launchd_services() {
    run_root launchctl list

    local -a lines data_lines
    lines=("${(@f)ROOT_CMD_OUTPUT}")
    data_lines=("${lines[@]:1}")

    local count=0
    local -a labels=()
    local line
    for line in "${data_lines[@]}"; do
        [[ -z "$line" ]] && continue
        local -a words
        words=(${=line})
        local pid="${words[1]}" label="${words[3]}"
        if [[ "$pid" != "-" && "$label" != com.apple.* ]]; then
            count=$((count + 1))
            labels+=("$label")
        fi
    done

    local joined
    joined=$(printf '%s\n' "${labels[@]}")

    # Always INFO: this is inventory, not a judgement.
    add_audit_result --category 'System Services & Daemon Exposure' --control 'Non-Apple Running launchd Services' \
        --status INFO --severity Informational --current "$count non-Apple running service(s)" --details "$joined" \
        --recommended 'N/A' --cis-macos 'CIS-macOS 5.7' --mscp 'N/A' \
        --recommendation 'Informational only.'
}

# --- CIS Apple macOS 26 Tahoe v1.0.0 sections 4.1-4.3 ---

check_bonjour_advertising_disabled() {
    evaluate_managed_pref --category 'System Services & Daemon Exposure' --control 'Bonjour Advertising Disabled' \
        --severity Low --suite com.apple.mDNSResponder --key NoMulticastAdvertisements --expect 1 \
        --cis 'CIS 4.1, 4.8' --nist 'CM-7' --mitre 'T1046 (Network Service Discovery)' --iso27001 'A.8.20' \
        --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 4.1' --mscp 'os_bonjour_disable' \
        --recommendation 'Disable Bonjour service advertising: "sudo defaults write /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements -bool true", or via profile.'
}

check_http_server_disabled() {
    run_root launchctl list
    local -a fw
    fw=(--recommended 'org.apache.httpd not loaded' --cis 'CIS 4.1, 4.8' --nist 'CM-7'
        --mitre 'T1190 (Exploit Public-Facing Application)' --iso27001 'A.8.20' --nis2 'Art.21(2)(d)'
        --cis-macos 'CIS-macOS 4.2' --mscp 'os_httpd_disable')
    if [[ $ROOT_CMD_STATUS -ne 0 ]]; then
        add_audit_result --category 'System Services & Daemon Exposure' --control 'Built-in HTTP Server Disabled' \
            --status WARN --severity Low --current "launchctl query failed: $ROOT_CMD_OUTPUT" "${fw[@]}" \
            --recommendation 'Verify manually with "sudo launchctl list | grep org.apache.httpd".'
    elif [[ "$ROOT_CMD_OUTPUT" == *"org.apache.httpd"* ]]; then
        add_audit_result --category 'System Services & Daemon Exposure' --control 'Built-in HTTP Server Disabled' \
            --status FAIL --severity Medium --current 'org.apache.httpd is loaded' "${fw[@]}" \
            --recommendation 'Stop and disable the built-in Apache server: "sudo launchctl disable system/org.apache.httpd && sudo launchctl bootout system/org.apache.httpd".'
    else
        add_audit_result --category 'System Services & Daemon Exposure' --control 'Built-in HTTP Server Disabled' \
            --status PASS --severity Medium --current 'org.apache.httpd is not loaded' "${fw[@]}" \
            --recommendation 'No action required.'
    fi
}

_nfs_server_check() {
    local exports_path="$1"
    run_root nfsd status
    local -a fw
    fw=(--recommended 'nfsd service disabled and no /etc/exports' --cis 'CIS 4.1, 4.8' --nist 'CM-7, AC-3'
        --mitre 'T1039 (Data from Network Shared Drive)' --iso27001 'A.8.20' --nis2 'Art.21(2)(d)'
        --cis-macos 'CIS-macOS 4.3' --mscp 'os_nfsd_disable')

    local service_state running=0
    service_state=$(print -r -- "$ROOT_CMD_OUTPUT" | awk '/nfsd service/ {print $NF; exit}')
    [[ "$ROOT_CMD_OUTPUT" == *"nfsd is running"* ]] && running=1

    if [[ -z "$service_state" ]]; then
        add_audit_result --category 'System Services & Daemon Exposure' --control 'NFS Server Disabled' \
            --status WARN --severity Low --current "nfsd status query failed: $ROOT_CMD_OUTPUT" "${fw[@]}" \
            --recommendation 'Verify manually with "sudo nfsd status".'
    elif [[ $running -eq 1 || -e "$exports_path" ]]; then
        add_audit_result --category 'System Services & Daemon Exposure' --control 'NFS Server Disabled' \
            --status FAIL --severity Medium \
            --current "nfsd service $service_state, $( (( running )) && print running || print 'not running'), $exports_path $( [[ -e $exports_path ]] && print present || print absent)" "${fw[@]}" \
            --recommendation "Disable the NFS server and remove its export list: sudo nfsd disable && sudo rm $exports_path"
    elif [[ "$service_state" == "enabled" ]]; then
        # launchd-enabled but dormant: nfsd only starts when /etc/exports
        # exists. CIS still wants it disabled; not an active exposure.
        add_audit_result --category 'System Services & Daemon Exposure' --control 'NFS Server Disabled' \
            --status WARN --severity Medium --current "nfsd service enabled but not running (no $exports_path)" "${fw[@]}" \
            --recommendation 'Disable the dormant NFS service so creating /etc/exports cannot silently start it: "sudo nfsd disable".'
    else
        add_audit_result --category 'System Services & Daemon Exposure' --control 'NFS Server Disabled' \
            --status PASS --severity Medium --current "nfsd service $service_state, no $exports_path" "${fw[@]}" \
            --recommendation 'No action required.'
    fi
}

check_nfs_server_disabled() {
    _nfs_server_check /etc/exports
}

# ---- 36-kernel-boot.zsh ----
#
# Domain 27: Kernel & Boot Security

check_boot_security_policy() {
    write_section_banner 'Kernel & Boot Security - Boot Security Policy'

    if ! is_apple_silicon; then
        add_audit_result --category 'Kernel & Boot Security' --control 'Boot Security Policy' \
            --status INFO --severity Informational \
            --current 'Not queryable from a running session — Startup Security Utility settings can only be verified by booting into macOS Recovery on Intel Macs with a T2 chip' \
            --recommended 'N/A' \
            --cis 'CIS 10.5' --nist 'SI-7' --mitre 'T1542.001 (System Firmware)' --iso27001 'A.8.24' \
            --nis2 'Art.21(2)(d)' --nsa 'NSA/CISA Boot Integrity Guidance' --cis-macos 'CIS-macOS 5.1.1' --mscp 'os_secure_boot_level_full_enforce' \
            --recommendation 'Informational only.'
        return
    fi

    run_root bputil -d

    # Real "bputil -d" output (verified live against actual root output,
    # not the plan's assumed "Full Security"/"Reduced Security"/
    # "Permissive Security" phrases — those never appear anywhere) is a
    # long field dump; the security mode is a single bare word ("Full",
    # "Reduced", or "Permissive") on a "Security Mode:" line, e.g.
    # "Security Mode:               Full       (smb0): absent". The full
    # dump (hashes, UUIDs, every other field) goes to --details for
    # anyone who wants to dig deeper — --current stays a one-line summary.
    local mode_line mode=""
    mode_line=$(print -r -- "$ROOT_CMD_OUTPUT" | grep -m1 '^Security Mode:')
    if [[ "$mode_line" =~ 'Security Mode:[[:space:]]+([A-Za-z]+)' ]]; then
        mode="${match[1]}"
    fi

    case "$mode" in
        Full)
            add_audit_result --category 'Kernel & Boot Security' --control 'Boot Security Policy' \
                --status PASS --severity High --current 'Security Mode: Full' --details "$ROOT_CMD_OUTPUT" \
                --recommended 'Full Security' \
                --cis 'CIS 10.5' --nist 'SI-7' --mitre 'T1542.001 (System Firmware)' --iso27001 'A.8.24' \
                --nis2 'Art.21(2)(d)' --nsa 'NSA/CISA Boot Integrity Guidance' --cis-macos 'CIS-macOS 5.1.1' --mscp 'os_secure_boot_level_full_enforce' \
                --recommendation 'No action required.'
            ;;
        Reduced)
            add_audit_result --category 'Kernel & Boot Security' --control 'Boot Security Policy' \
                --status WARN --severity Medium --current 'Security Mode: Reduced' --details "$ROOT_CMD_OUTPUT" \
                --recommended 'Full Security' \
                --cis 'CIS 10.5' --nist 'SI-7' --mitre 'T1542.001 (System Firmware)' --iso27001 'A.8.24' \
                --nis2 'Art.21(2)(d)' --nsa 'NSA/CISA Boot Integrity Guidance' --cis-macos 'CIS-macOS 5.1.1' --mscp 'os_secure_boot_level_full_enforce' \
                --recommendation 'Consider Full Security unless a specific, documented need (e.g. running unsigned kexts) requires Reduced.'
            ;;
        Permissive)
            add_audit_result --category 'Kernel & Boot Security' --control 'Boot Security Policy' \
                --status FAIL --severity High --current 'Security Mode: Permissive' --details "$ROOT_CMD_OUTPUT" \
                --recommended 'Full Security' \
                --cis 'CIS 10.5' --nist 'SI-7' --mitre 'T1542.001 (System Firmware)' --iso27001 'A.8.24' \
                --nis2 'Art.21(2)(d)' --nsa 'NSA/CISA Boot Integrity Guidance' --cis-macos 'CIS-macOS 5.1.1' --mscp 'os_secure_boot_level_full_enforce' \
                --recommendation 'This disables nearly all boot-chain integrity verification; restore via Startup Security Utility in Recovery unless deliberately required for development.'
            ;;
        *)
            add_audit_result --category 'Kernel & Boot Security' --control 'Boot Security Policy' \
                --status WARN --severity Low --current 'Query failed or unrecognized output' --details "$ROOT_CMD_OUTPUT" \
                --recommended 'Full Security' \
                --cis-macos 'CIS-macOS 5.1.1' --mscp 'os_secure_boot_level_full_enforce' \
                --recommendation 'Unable to determine boot security policy; verify manually with "sudo bputil -d".'
            ;;
    esac
}

check_authenticated_root_status() {
    run_root csrutil authenticated-root status

    if [[ "$ROOT_CMD_OUTPUT" == *"enabled"* ]]; then
        add_audit_result --category 'Kernel & Boot Security' --control 'Authenticated Root Status' \
            --status PASS --severity High --current "$ROOT_CMD_OUTPUT" \
            --recommended 'Authenticated Root status: enabled' \
            --cis 'CIS 10.5' --nist 'SI-7' --mitre 'T1542.001 (System Firmware)' --iso27001 'A.8.24' \
            --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 5.1.1' --mscp 'os_sip_enable' \
            --recommendation 'No action required.'
    elif [[ "$ROOT_CMD_OUTPUT" == *"disabled"* ]]; then
        add_audit_result --category 'Kernel & Boot Security' --control 'Authenticated Root Status' \
            --status FAIL --severity High --current "$ROOT_CMD_OUTPUT" \
            --recommended 'Authenticated Root status: enabled' \
            --cis 'CIS 10.5' --nist 'SI-7' --mitre 'T1542.001 (System Firmware)' --iso27001 'A.8.24' \
            --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 5.1.1' --mscp 'os_sip_enable' \
            --recommendation 'Re-enable via "csrutil authenticated-root enable" from Recovery — this protects the integrity of the signed system volume against offline tampering.'
    else
        add_audit_result --category 'Kernel & Boot Security' --control 'Authenticated Root Status' \
            --status WARN --severity Low --current "Query failed or unrecognized output: $ROOT_CMD_OUTPUT" \
            --recommended 'Authenticated Root status: enabled' \
            --cis-macos 'CIS-macOS 5.1.1' --mscp 'os_sip_enable' \
            --recommendation 'Unable to determine authenticated root status; verify manually with "csrutil authenticated-root status".'
    fi
}

check_nvram_boot_args() {
    run_root nvram boot-args

    local -a parts
    parts=(${=ROOT_CMD_OUTPUT})
    local value="${(j: :)parts[2,-1]}"

    if [[ $ROOT_CMD_STATUS -ne 0 || -z "$value" ]]; then
        add_audit_result --category 'Kernel & Boot Security' --control 'NVRAM Boot-Args' \
            --status PASS --severity Low --current 'No boot-args set' \
            --recommended 'No boot-args set' \
            --cis 'CIS 10.5' --nist 'SI-7, CM-6' --mitre 'T1542.001 (System Firmware)' --iso27001 'A.8.24' \
            --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 5.1.1' --mscp 'N/A' \
            --recommendation 'No action required.'
    elif [[ "$value" == *"amfi_get_out_of_my_way=1"* || "$value" == *"cs_enforcement_disable=1"* || "$value" == *"-arm64e_preview_abi"* ]]; then
        add_audit_result --category 'Kernel & Boot Security' --control 'NVRAM Boot-Args' \
            --status FAIL --severity Critical --current "$value" \
            --recommended 'No boot-args set' \
            --cis 'CIS 10.5' --nist 'SI-7, CM-6' --mitre 'T1542.001 (System Firmware)' --iso27001 'A.8.24' \
            --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 5.1.1' --mscp 'N/A' \
            --recommendation 'Clear the dangerous boot-arg immediately — these disable code-signing/AMFI enforcement at the kernel level; treat as a possible active-compromise indicator.'
    else
        add_audit_result --category 'Kernel & Boot Security' --control 'NVRAM Boot-Args' \
            --status WARN --severity Low --current "$value" \
            --recommended 'No boot-args set' \
            --cis 'CIS 10.5' --nist 'SI-7, CM-6' --mitre 'T1542.001 (System Firmware)' --iso27001 'A.8.24' \
            --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 5.1.1' --mscp 'N/A' \
            --recommendation 'Review the custom boot-arg for legitimacy.'
    fi
}

check_thirdparty_kext_inventory() {
    run_root kmutil showloaded

    local -a lines data_lines
    lines=("${(@f)ROOT_CMD_OUTPUT}")
    data_lines=("${lines[@]:1}")

    local -a thirdparty=()
    local line
    for line in "${data_lines[@]}"; do
        [[ -z "$line" ]] && continue
        [[ "$line" == *"com.apple."* ]] && continue
        local -a words
        words=(${=line})
        thirdparty+=("${words[-1]}")
    done

    if (( ${#thirdparty[@]} == 0 )); then
        add_audit_result --category 'Kernel & Boot Security' --control 'Third-Party Kernel Extension Inventory' \
            --status PASS --severity Informational --current 'No non-Apple kernel extensions loaded' \
            --recommended 'No non-Apple kernel extensions loaded' \
            --cis 'CIS 2.5' --nist 'CM-7, SI-7' --mitre 'T1547.006 (Kernel Modules and Extensions)' --iso27001 'A.8.19' \
            --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 5.1' --mscp 'N/A' \
            --recommendation 'No action required.'
    else
        local joined
        joined=$(printf '%s\n' "${thirdparty[@]}")
        add_audit_result --category 'Kernel & Boot Security' --control 'Third-Party Kernel Extension Inventory' \
            --status WARN --severity High --current "${#thirdparty[@]} non-Apple kext(s) loaded" \
            --details "$joined" \
            --recommended 'No non-Apple kernel extensions loaded' \
            --cis 'CIS 2.5' --nist 'CM-7, SI-7' --mitre 'T1547.006 (Kernel Modules and Extensions)' --iso27001 'A.8.19' \
            --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 5.1' --mscp 'N/A' \
            --recommendation 'Legacy kernel extensions run with full kernel privileges — migrate to a System Extension where the vendor supports it, and confirm each loaded kext is expected.'
    fi
}

# ---- 37-virtualization.zsh ----
#
# Domain 28: Virtualization & Container Escape Surface
#
# Never invokes docker ps/docker version or any command that talks to a
# container daemon that might be unreachable — checks only for
# process/file presence, to keep the audit fast and hang-proof.

check_docker_desktop_presence() {
    write_section_banner 'Virtualization & Container Escape Surface - Docker Desktop Presence'
    run_root pgrep -f 'Docker.app/Contents/MacOS/Docker'

    # Always INFO: process presence only, no live daemon calls.
    if [[ $ROOT_CMD_STATUS -eq 0 ]]; then
        add_audit_result --category 'Virtualization & Container Escape Surface' --control 'Docker Desktop Presence' \
            --status INFO --severity Informational --current 'Docker Desktop is running' \
            --recommended 'N/A' --cis-macos 'CIS-macOS 5.8' --mscp 'N/A' \
            --recommendation 'Informational only.'
    else
        add_audit_result --category 'Virtualization & Container Escape Surface' --control 'Docker Desktop Presence' \
            --status INFO --severity Informational --current 'Docker Desktop is not running' \
            --recommended 'N/A' --cis-macos 'CIS-macOS 5.8' --mscp 'N/A' \
            --recommendation 'Informational only.'
    fi
}

# Checks existence (not process state) of a set of VM hypervisor app
# bundles. Directly testable against scratch paths.
_vm_hypervisor_apps_check() {
    local -a candidates=("$@")
    local -a found=()
    local app

    for app in "${candidates[@]}"; do
        run_root test -d "$app"
        [[ $ROOT_CMD_STATUS -eq 0 ]] && found+=("${app:t}")
    done

    local current
    if (( ${#found[@]} > 0 )); then
        local joined
        joined=$(printf '%s, ' "${found[@]}")
        joined="${joined%, }"
        current="Found: $joined"
    else
        current="None found"
    fi

    # Always INFO: this is inventory, not a judgement.
    add_audit_result --category 'Virtualization & Container Escape Surface' --control 'VM Hypervisor Apps Inventory' \
        --status INFO --severity Informational --current "$current" \
        --recommended 'N/A' --cis-macos 'CIS-macOS 5.8' --mscp 'N/A' \
        --recommendation 'Informational only. Review each VM host'"'"'s shared-folder/clipboard configuration manually, since it cannot be safely enumerated without invoking the hypervisor'"'"'s own tooling.'
}

check_vm_hypervisor_apps_inventory() {
    _vm_hypervisor_apps_check '/Applications/UTM.app' '/Applications/Parallels Desktop.app' '/Applications/VMware Fusion.app'
}

# ---- 38-dlp.zsh ----
#
# Domain 29: Data Loss Prevention & Sensitive Data

check_screenshot_save_location_cloud_exposure() {
    write_section_banner 'Data Loss Prevention & Sensitive Data - Screenshot Save Location Cloud Exposure'
    local location
    location=$(defaults_read_as_user_safe 'com.apple.screencapture' 'location' '~/Desktop')

    if [[ "$location" == *"Mobile Documents"* ]]; then
        add_audit_result --category 'Data Loss Prevention & Sensitive Data' --control 'Screenshot Save Location Cloud Exposure' \
            --status WARN --severity Low --current "$location" \
            --recommended 'A non-iCloud save location' \
            --cis 'CIS 3.11' --nist 'SI-4' --iso27001 'A.8.12' --nis2 'Art.21(2)(h)' --cis-macos 'CIS-macOS 2.11' --mscp 'N/A' \
            --recommendation 'Be aware screenshots may contain sensitive on-screen data and could sync to iCloud from this location; change the save location in Screenshot app preferences if that'"'"'s undesired.'
    else
        add_audit_result --category 'Data Loss Prevention & Sensitive Data' --control 'Screenshot Save Location Cloud Exposure' \
            --status PASS --severity Low --current "$location" \
            --recommended 'A non-iCloud save location' \
            --cis 'CIS 3.11' --nist 'SI-4' --iso27001 'A.8.12' --nis2 'Art.21(2)(h)' --cis-macos 'CIS-macOS 2.11' --mscp 'N/A' \
            --recommendation 'No action required.'
    fi
}

check_handoff_universal_clipboard_note() {
    # No command: always INFO, per honesty-over-false-precision (same
    # style as Task 16's FIPS check) — Handoff/Universal Clipboard
    # exposure across a user's trusted-device set cannot be queried
    # reliably from a single documented CLI key across macOS 15/26.
    add_audit_result --category 'Data Loss Prevention & Sensitive Data' --control 'Handoff / Universal Clipboard' \
        --status INFO --severity Informational \
        --current 'Handoff/Universal Clipboard exposure across trusted devices cannot be reliably queried from the command line; review manually in System Settings > General > AirDrop & Handoff' \
        --recommended 'N/A' --cis-macos 'CIS-macOS 2.11' --mscp 'N/A' \
        --recommendation 'Informational only.'
}

# ---- 39-inventory.zsh ----
#
# Domain 30: System Inventory & Asset Information

check_system_hardware_summary() {
    write_section_banner 'System Inventory & Asset Information - System Hardware Summary'
    run_root system_profiler SPHardwareDataType

    local model_name model_identifier chip ram
    model_name=$(print -r -- "$ROOT_CMD_OUTPUT" | grep -m1 'Model Name:' | sed 's/^[[:space:]]*Model Name:[[:space:]]*//')
    model_identifier=$(print -r -- "$ROOT_CMD_OUTPUT" | grep -m1 'Model Identifier:' | sed 's/^[[:space:]]*Model Identifier:[[:space:]]*//')
    chip=$(print -r -- "$ROOT_CMD_OUTPUT" | grep -m1 'Chip:' | sed 's/^[[:space:]]*Chip:[[:space:]]*//')
    ram=$(print -r -- "$ROOT_CMD_OUTPUT" | grep -m1 'Memory:' | sed 's/^[[:space:]]*Memory:[[:space:]]*//')

    # Always INFO: this is inventory, not a judgement. Duplicates some of
    # Domain 1's hardware parsing by design — this is the same underlying
    # facts read for the asset-inventory/System-Overview angle, not the
    # boot/platform-integrity angle.
    add_audit_result --category 'System Inventory & Asset Information' --control 'System Hardware Summary' \
        --status INFO --severity Informational \
        --current "Model Name: ${model_name:-Unknown}; Model Identifier: ${model_identifier:-Unknown}; Chip: ${chip:-Unknown}; Memory: ${ram:-Unknown}" \
        --recommended 'N/A' --cis-macos 'CIS-macOS 1.1' --mscp 'N/A' \
        --recommendation 'Informational only.'
}

check_os_version_and_build() {
    run_root sw_vers

    local product_name product_version build_version line
    line=$(print -r -- "$ROOT_CMD_OUTPUT" | grep '^ProductName:')
    product_name="${${(z)line}[-1]}"
    line=$(print -r -- "$ROOT_CMD_OUTPUT" | grep '^ProductVersion:')
    product_version="${${(z)line}[-1]}"
    line=$(print -r -- "$ROOT_CMD_OUTPUT" | grep '^BuildVersion:')
    build_version="${${(z)line}[-1]}"

    # Always INFO: this is inventory, not a judgement.
    add_audit_result --category 'System Inventory & Asset Information' --control 'OS Version & Build' \
        --status INFO --severity Informational \
        --current "$product_name $product_version (Build $build_version)" \
        --recommended 'N/A' --cis-macos 'CIS-macOS 1.1' --mscp 'N/A' \
        --recommendation 'Informational only.'
}

check_disk_space_utilization() {
    run_root df -H /

    local -a lines data_line words
    lines=("${(@f)ROOT_CMD_OUTPUT}")
    data_line="${lines[2]}"
    words=(${=data_line})
    local capacity="${words[5]}"
    local used_pct="${capacity%\%}"
    local free_pct=$(( 100 - used_pct ))

    if (( free_pct < 10 )); then
        add_audit_result --category 'System Inventory & Asset Information' --control 'Disk Space Utilization' \
            --status WARN --severity Low --current "$capacity used ($free_pct% free)" \
            --recommended '>=10% free' --cis-macos 'CIS-macOS 1.1' --mscp 'N/A' \
            --recommendation 'Free up disk space — low free space can block macOS updates and Time Machine snapshots.'
    else
        add_audit_result --category 'System Inventory & Asset Information' --control 'Disk Space Utilization' \
            --status PASS --severity Low --current "$capacity used ($free_pct% free)" \
            --recommended '>=10% free' --cis-macos 'CIS-macOS 1.1' --mscp 'N/A' \
            --recommendation 'No action required.'
    fi
}

check_installed_application_count() {
    run_root find /Applications -maxdepth 1 -name '*.app'

    local -a apps names=()
    apps=("${(@f)ROOT_CMD_OUTPUT}")
    local a
    for a in "${apps[@]}"; do
        [[ -n "$a" ]] && names+=("${a:t}")
    done

    local joined
    joined=$(printf '%s\n' "${names[@]}")

    # Always INFO: reused here only as a count for the System Overview
    # panel, not re-judged.
    add_audit_result --category 'System Inventory & Asset Information' --control 'Installed Application Count' \
        --status INFO --severity Informational --current "${#names[@]} application(s)" \
        --details "$joined" \
        --recommended 'N/A' --cis-macos 'CIS-macOS 1.1' --mscp 'N/A' \
        --recommendation 'Informational only.'
}

check_uptime_and_last_boot() {
    run_root sysctl -n kern.boottime

    local sec_str epoch now uptime_secs days hours boot_date
    # Anchored on "{ sec = " specifically: a plain "sec = [0-9]+" pattern
    # would also match inside "usec = 0" (u-SEC), corrupting the parse.
    if [[ "$ROOT_CMD_OUTPUT" =~ '\{ sec = ([0-9]+)' ]]; then
        sec_str="${match[1]}"
    else
        sec_str=""
    fi

    if [[ -z "$sec_str" ]]; then
        add_audit_result --category 'System Inventory & Asset Information' --control 'Uptime & Last Boot' \
            --status INFO --severity Informational --current 'Unable to determine boot time' \
            --recommended 'N/A' --cis-macos 'CIS-macOS 1.1' --mscp 'N/A' \
            --recommendation 'Informational only.'
        return
    fi

    epoch=$sec_str
    now=$(date +%s)
    uptime_secs=$(( now - epoch ))
    days=$(( uptime_secs / 86400 ))
    hours=$(( (uptime_secs % 86400) / 3600 ))
    boot_date=$(date -j -f "%s" "$epoch" "+%Y-%m-%d %H:%M:%S" 2>/dev/null)

    # Always INFO: this is inventory, not a judgement.
    add_audit_result --category 'System Inventory & Asset Information' --control 'Uptime & Last Boot' \
        --status INFO --severity Informational --current "Last boot: $boot_date; Uptime: ${days}d ${hours}h" \
        --recommended 'N/A' --cis-macos 'CIS-macOS 1.1' --mscp 'N/A' \
        --recommendation 'Informational only.'
}

# ---- 40-apple-intelligence.zsh ----
#
# Domain 31: Apple Intelligence, Siri & Analytics
#
# CIS Apple macOS 26 Tahoe Benchmark v1.0.0 sections 2.5, 2.6.3, 2.6.4,
# 2.9 and 2.18. Every control here is a profile-enforced
# com.apple.applicationaccess / assistant key, audited through
# evaluate_managed_pref (01-core.zsh) — unset keys are WARN, not FAIL.

typeset -g AI_CATEGORY='Apple Intelligence, Siri & Analytics'

check_external_intelligence_disabled() {
    write_section_banner "$AI_CATEGORY - External Intelligence Extensions"
    evaluate_managed_pref --category "$AI_CATEGORY" --control 'External Intelligence Integrations Disabled' \
        --severity Medium --suite com.apple.applicationaccess --key allowExternalIntelligenceIntegrations --expect 0 \
        --cis 'CIS 4.1, 4.8, 15.3' --nist 'AC-20, SC-7' --mitre 'T1567 (Exfiltration Over Web Service)' \
        --iso27001 'A.5.14' --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 2.5.1.1' \
        --mscp 'system_settings_external_intelligence_disable' \
        --recommendation 'Deploy a Restrictions profile with allowExternalIntelligenceIntegrations=false so Apple Intelligence cannot hand requests to third-party models (e.g. ChatGPT).'
}

check_external_intelligence_sign_in_disabled() {
    evaluate_managed_pref --category "$AI_CATEGORY" --control 'External Intelligence Sign-In Disabled' \
        --severity Medium --suite com.apple.applicationaccess --key allowExternalIntelligenceIntegrationsSignIn --expect 0 \
        --cis 'CIS 4.1, 4.8, 15.3' --nist 'AC-20' --iso27001 'A.5.14' --nis2 'Art.21(2)(d)' \
        --cis-macos 'CIS-macOS 2.5.1.1' --mscp 'system_settings_external_intelligence_sign_in_disable' \
        --recommendation 'Deploy a Restrictions profile with allowExternalIntelligenceIntegrationsSignIn=false so users cannot sign in to third-party intelligence providers.'
}

check_writing_tools_disabled() {
    evaluate_managed_pref --category "$AI_CATEGORY" --control 'Writing Tools Disabled' \
        --severity Low --suite com.apple.applicationaccess --key allowWritingTools --expect 0 \
        --cis 'CIS 4.1, 4.8, 15.3' --nist 'AC-20' --iso27001 'A.5.14' --nis2 'Art.21(2)(d)' \
        --cis-macos 'CIS-macOS 2.5.1.2' --mscp 'os_writing_tools_disable' \
        --recommendation 'Deploy a Restrictions profile with allowWritingTools=false if organizational data must not be processed by Apple Intelligence Writing Tools.'
}

check_mail_summarization_disabled() {
    evaluate_managed_pref --category "$AI_CATEGORY" --control 'Mail Summarization Disabled' \
        --severity Low --suite com.apple.applicationaccess --key allowMailSummary --expect 0 \
        --cis 'CIS 4.1, 4.8, 15.3' --nist 'AC-20' --iso27001 'A.5.14' --nis2 'Art.21(2)(d)' \
        --cis-macos 'CIS-macOS 2.5.1.3' --mscp 'os_mail_summary_disable' \
        --recommendation 'Deploy a Restrictions profile with allowMailSummary=false.'
}

check_notes_transcription_disabled() {
    evaluate_managed_pref --category "$AI_CATEGORY" --control 'Notes Transcription Disabled' \
        --severity Low --suite com.apple.applicationaccess --key allowNotesTranscription --expect 0 \
        --cis 'CIS 4.1, 4.8, 15.3' --nist 'AC-20' --iso27001 'A.5.14' --nis2 'Art.21(2)(d)' \
        --cis-macos 'CIS-macOS 2.5.1.4' --mscp 'os_notes_transcription_disable' \
        --recommendation 'Deploy a Restrictions profile with allowNotesTranscription=false.'
}

check_notes_summarization_disabled() {
    evaluate_managed_pref --category "$AI_CATEGORY" --control 'Notes Transcription Summary Disabled' \
        --severity Low --suite com.apple.applicationaccess --key allowNotesTranscriptionSummary --expect 0 \
        --cis 'CIS 4.1, 4.8, 15.3' --nist 'AC-20' --iso27001 'A.5.14' --nis2 'Art.21(2)(d)' \
        --cis-macos 'CIS-macOS 2.5.1.4' --mscp 'os_notes_transcription_summary_disable' \
        --recommendation 'Deploy a Restrictions profile with allowNotesTranscriptionSummary=false.'
}

check_siri_disabled() {
    evaluate_managed_pref --category "$AI_CATEGORY" --control 'Siri Disabled' \
        --severity Low --suite com.apple.applicationaccess --key allowAssistant --expect 0 \
        --cis 'CIS 4.1, 4.8' --nist 'CM-7' --mitre 'T1123 (Audio Capture)' --iso27001 'A.8.9' \
        --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 2.5.2.1' --mscp 'system_settings_siri_disable' \
        --recommendation 'Deploy a Restrictions profile with allowAssistant=false, per your organization'"'"'s Siri policy.'
}

check_improve_siri_dictation_disabled() {
    evaluate_managed_pref --category "$AI_CATEGORY" --control 'Improve Siri & Dictation Disabled' \
        --severity Low --suite com.apple.assistant.support --key 'Siri Data Sharing Opt-In Status' --expect 2 \
        --cis 'CIS 4.1, 4.8' --nist 'CM-7, SI-12' --iso27001 'A.5.34' --nis2 'Art.21(2)(d)' \
        --cis-macos 'CIS-macOS 2.6.3.2' --mscp 'system_settings_improve_siri_dictation_disable' \
        --recommendation 'Disable System Settings > Privacy & Security > Analytics & Improvements > Improve Siri & Dictation (value 2 = opted out), or enforce it via profile.'
}

check_improve_assistive_voice_disabled() {
    evaluate_managed_pref --category "$AI_CATEGORY" --control 'Improve Assistive Voice Features Disabled' \
        --severity Low --suite com.apple.Accessibility --key AXSAudioDonationSiriImprovementEnabled --expect 0 \
        --cis 'CIS 4.1, 4.8' --nist 'CM-7, SI-12' --iso27001 'A.5.34' --nis2 'Art.21(2)(d)' \
        --cis-macos 'CIS-macOS 2.6.3.3' --mscp 'system_settings_improve_assistive_voice_disable' \
        --recommendation 'Disable System Settings > Privacy & Security > Analytics & Improvements > Improve Assistive Voice Features, or enforce AXSAudioDonationSiriImprovementEnabled=false via profile.'
}

check_share_with_app_developers_disabled() {
    evaluate_managed_pref --category "$AI_CATEGORY" --control 'Share with App Developers Disabled' \
        --severity Low --suite com.apple.applicationaccess --key allowDiagnosticSubmission --expect 0 \
        --cis 'CIS 4.1, 4.8' --nist 'CM-7, SI-12' --iso27001 'A.5.34' --nis2 'Art.21(2)(d)' \
        --cis-macos 'CIS-macOS 2.6.3.4' --mscp 'system_settings_diagnostics_reports_disable' \
        --recommendation 'Deploy a Restrictions profile with allowDiagnosticSubmission=false to stop diagnostic data being shared with Apple and third-party developers.'
}

check_limit_ad_tracking_enabled() {
    evaluate_managed_pref --category "$AI_CATEGORY" --control 'Personalized Advertising Disabled' \
        --severity Low --suite com.apple.applicationaccess --key allowApplePersonalizedAdvertising --expect 0 \
        --cis 'CIS 4.8' --nist 'CM-7' --iso27001 'A.5.34' --nis2 'Art.21(2)(d)' \
        --cis-macos 'CIS-macOS 2.6.4' --mscp 'system_settings_personalized_advertising_disable' \
        --recommendation 'Deploy a Restrictions profile with allowApplePersonalizedAdvertising=false.'
}

check_help_apple_improve_search_disabled() {
    evaluate_managed_pref --category "$AI_CATEGORY" --control 'Help Apple Improve Search Disabled' \
        --severity Low --suite com.apple.assistant.support --key 'Search Queries Data Sharing Status' --expect 2 \
        --cis 'CIS 4.1, 4.8' --nist 'CM-7, SI-12' --iso27001 'A.5.34' --nis2 'Art.21(2)(d)' \
        --cis-macos 'CIS-macOS 2.9.1' --mscp 'system_settings_improve_search_disable' \
        --recommendation 'Disable System Settings > Spotlight > Help Apple Improve Search (value 2 = opted out), or enforce it via profile.'
}

check_on_device_dictation_enforced() {
    evaluate_managed_pref --category "$AI_CATEGORY" --control 'On-Device Dictation Enforced' \
        --severity Low --suite com.apple.applicationaccess --key forceOnDeviceOnlyDictation --expect 1 \
        --cis 'CIS 4.1' --nist 'SC-7, SI-12' --iso27001 'A.5.34' --nis2 'Art.21(2)(d)' \
        --cis-macos 'CIS-macOS 2.18.1' --mscp 'os_on_device_dictation_enforce' \
        --recommendation 'Deploy a Restrictions profile with forceOnDeviceOnlyDictation=true so dictated audio is never sent to Apple servers.'
}

# ---- 41-power-management.zsh ----
#
# Domain 32: Power Management & Sleep
#
# CIS Apple macOS 26 Tahoe Benchmark v1.0.0 section 2.10. All three read
# `pmset -g custom` / `pmset -b -g`; architecture-specific controls report
# INFO "not applicable" on the other architecture, matching 10-hardware.

typeset -g POWER_CATEGORY='Power Management & Sleep'

# Prints the value of a pmset setting, one line per power source listed
# in `pmset -g custom` output; with a section name ("Battery Power:"),
# only that section's value.
_pmset_values() {
    local output="$1" setting="$2" section="${3:-}"
    print -r -- "$output" | awk -v k="$setting" -v s="$section" '
        /^[A-Za-z].*:$/ { in_section = (s == "" || $0 == s); next }
        (s == "" || in_section) && $1 == k { print $2 }'
}

check_sleep_enabled_apple_silicon() {
    write_section_banner "$POWER_CATEGORY - Sleep & Display Sleep"
    if ! is_apple_silicon; then
        add_audit_result --category "$POWER_CATEGORY" --control 'Sleep & Display Sleep (Apple Silicon Laptops)' \
            --status INFO --severity Informational --current 'Not applicable: Intel Mac (see Power Nap control)' \
            --recommended 'N/A' --cis-macos 'CIS-macOS 2.10.1.2' --mscp 'os_sleep_and_display_sleep_apple_silicon_enable' \
            --recommendation 'Informational only.'
        return 0
    fi

    run_root system_profiler SPHardwareDataType
    if [[ "$ROOT_CMD_OUTPUT" != *MacBook* ]]; then
        add_audit_result --category "$POWER_CATEGORY" --control 'Sleep & Display Sleep (Apple Silicon Laptops)' \
            --status INFO --severity Informational --current 'Not applicable: not a MacBook (no battery power profile)' \
            --recommended 'N/A' --cis-macos 'CIS-macOS 2.10.1.2' --mscp 'os_sleep_and_display_sleep_apple_silicon_enable' \
            --recommendation 'Informational only.'
        return 0
    fi

    # Deliberately not the CIS command ("pmset -b -g"): verified live that
    # it prints the "Currently in use" profile, i.e. the AC settings
    # whenever the laptop is plugged in. The battery section of
    # "pmset -g custom" is what the recommendation actually targets.
    run_root pmset -g custom
    local pm_output="$ROOT_CMD_OUTPUT" pm_status=$ROOT_CMD_STATUS
    local sleep_val display_val
    sleep_val=$(_pmset_values "$pm_output" sleep 'Battery Power:' | head -1)
    display_val=$(_pmset_values "$pm_output" displaysleep 'Battery Power:' | head -1)

    # CIS: "If the screen saver is properly configured to the benchmark
    # (15 minutes or less), then this recommendation will also pass no
    # matter the sleep and displaysleep setting."
    local idle
    idle=$(managed_pref_read com.apple.screensaver idleTime)
    local current="sleep=${sleep_val:-unknown}, displaysleep=${display_val:-unknown}, screensaver idleTime=${idle:-not set}"
    local -a fw
    fw=(--recommended 'sleep 1-15 min, displaysleep 1-10 min and <= sleep (or screensaver idleTime <= 900s)'
        --cis 'CIS 4.1' --nist 'AC-11' --mitre 'T1200 (Hardware Additions)' --iso27001 'A.8.1'
        --nis2 'Art.21(2)(i)' --cis-macos 'CIS-macOS 2.10.1.2' --mscp 'os_sleep_and_display_sleep_apple_silicon_enable')

    if [[ $pm_status -ne 0 || "$sleep_val" != <-> || "$display_val" != <-> ]]; then
        add_audit_result --category "$POWER_CATEGORY" --control 'Sleep & Display Sleep (Apple Silicon Laptops)' \
            --status WARN --severity Low --current "pmset query failed or unparseable: $current" "${fw[@]}" \
            --recommendation 'Verify battery sleep settings manually with "pmset -g custom".'
    elif [[ "$idle" == <-> ]] && (( idle > 0 && idle <= 900 )) \
         || (( sleep_val > 0 && sleep_val <= 15 && display_val > 0 && display_val <= 10 && display_val <= sleep_val )); then
        add_audit_result --category "$POWER_CATEGORY" --control 'Sleep & Display Sleep (Apple Silicon Laptops)' \
            --status PASS --severity Low --current "$current" "${fw[@]}" --recommendation 'No action required.'
    else
        add_audit_result --category "$POWER_CATEGORY" --control 'Sleep & Display Sleep (Apple Silicon Laptops)' \
            --status FAIL --severity Low --current "$current" "${fw[@]}" \
            --recommendation 'Set battery sleep to 15 minutes or less and display sleep to 10 minutes or less: "sudo pmset -b sleep 15 displaysleep 10".'
    fi
}

check_power_nap_disabled_intel() {
    if is_apple_silicon; then
        add_audit_result --category "$POWER_CATEGORY" --control 'Power Nap Disabled (Intel)' \
            --status INFO --severity Informational --current 'Not applicable: Apple Silicon Mac' \
            --recommended 'N/A' --cis-macos 'CIS-macOS 2.10.2' --mscp 'os_power_nap_disable' \
            --recommendation 'Informational only.'
        return 0
    fi

    run_root pmset -g custom
    local -a fw
    fw=(--recommended 'powernap 0 on every power source' --cis 'CIS 4.1, 4.8' --nist 'CM-7'
        --iso27001 'A.8.9' --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 2.10.2' --mscp 'os_power_nap_disable')

    if [[ $ROOT_CMD_STATUS -ne 0 ]]; then
        add_audit_result --category "$POWER_CATEGORY" --control 'Power Nap Disabled (Intel)' \
            --status WARN --severity Low --current "pmset query failed: $ROOT_CMD_OUTPUT" "${fw[@]}" \
            --recommendation 'Verify manually with "pmset -g custom".'
    elif _pmset_values "$ROOT_CMD_OUTPUT" powernap | grep -qx 1; then
        add_audit_result --category "$POWER_CATEGORY" --control 'Power Nap Disabled (Intel)' \
            --status FAIL --severity Low --current 'powernap 1 on at least one power source' "${fw[@]}" \
            --recommendation 'Disable Power Nap: "sudo pmset -a powernap 0".'
    else
        add_audit_result --category "$POWER_CATEGORY" --control 'Power Nap Disabled (Intel)' \
            --status PASS --severity Low --current 'powernap 0' "${fw[@]}" --recommendation 'No action required.'
    fi
}

check_wake_for_network_access_disabled() {
    run_root pmset -g custom
    local -a fw
    fw=(--recommended 'womp 0 on every power source' --cis 'CIS 4.8' --nist 'CM-7, AC-17'
        --mitre 'T1133 (External Remote Services)' --iso27001 'A.8.20' --nis2 'Art.21(2)(d)'
        --cis-macos 'CIS-macOS 2.10.3' --mscp 'system_settings_wake_network_access_disable')

    if [[ $ROOT_CMD_STATUS -ne 0 ]]; then
        add_audit_result --category "$POWER_CATEGORY" --control 'Wake for Network Access Disabled' \
            --status WARN --severity Low --current "pmset query failed: $ROOT_CMD_OUTPUT" "${fw[@]}" \
            --recommendation 'Verify manually with "pmset -g custom".'
        return 0
    fi

    local womp_values
    womp_values=$(_pmset_values "$ROOT_CMD_OUTPUT" womp | tr '\n' ' ')
    if [[ -z "${womp_values// /}" ]]; then
        # No womp line at all: hardware without Wake-on-LAN support.
        add_audit_result --category "$POWER_CATEGORY" --control 'Wake for Network Access Disabled' \
            --status PASS --severity Low --current 'No womp setting reported (not supported on this hardware)' "${fw[@]}" \
            --recommendation 'No action required.'
    elif [[ " $womp_values" == *" 1 "* ]]; then
        add_audit_result --category "$POWER_CATEGORY" --control 'Wake for Network Access Disabled' \
            --status FAIL --severity Low --current "womp values: $womp_values" "${fw[@]}" \
            --recommendation 'Disable Wake for network access: "sudo pmset -a womp 0".'
    else
        add_audit_result --category "$POWER_CATEGORY" --control 'Wake for Network Access Disabled' \
            --status PASS --severity Low --current "womp values: $womp_values" "${fw[@]}" \
            --recommendation 'No action required.'
    fi
}

# ---- 90-scoring.zsh ----
#
# Scoring & risk engine. Direct port of Get-CompliancePosture from the
# Windows tool: weighted score, PASS=full/WARN=half/FAIL=zero credit,
# INFO excluded entirely, tiered risk badge.

get_compliance_posture() {
    # Force the C locale for this function: under a comma-decimal locale
    # (e.g. de_DE.UTF-8 — a normal macOS regional setting, not exotic),
    # `printf '%.1f'` below would emit "71,4" instead of "71.4", and the
    # later `(( ${score} < 60 ))` arithmetic would then parse that comma as
    # zsh's arithmetic comma operator — silently misclassifying risk (e.g.
    # a real MEDIUM score flipping to HIGH). Verified live with
    # `LC_ALL=de_DE.UTF-8 zsh -c ...` during task review: both the
    # formatting and the downstream comparison break without this, and
    # `local LC_ALL=C` (not `LC_NUMERIC=C` alone, which did not fix it in
    # testing) resolves both in one line since it's scoped to this function
    # only, not exported process-wide.
    local LC_ALL=C
    local -A severity_weight
    severity_weight=(Critical 10 High 7 Medium 4 Low 2 Informational 0)

    # Seeded as floats (0.0, not 0): zsh arithmetic does C-style truncating
    # integer division when both operands of "/" are integers (e.g.
    # `$(( 10/20 ))` is 0, not 0.5) and only switches to floating-point once
    # either operand is already a float. Seeding here forces every later
    # addition to stay float-typed, so the final (earned/max) division below
    # is never silently truncated to 0 — verified with `zsh -c` during
    # planning, since this is easy to get wrong and would corrupt every score.
    local max_points=0.0 earned_points=0.0
    local total=${#AUDIT_STATUS[@]}
    local pass_count=0 fail_count=0 warn_count=0 info_count=0
    local critical_fails=0 high_fails=0
    local i

    for (( i = 1; i <= total; i++ )); do
        # Named status_val, not status: zsh's `status` is a read-only alias
        # for `$?` (verified with `zsh -c` — `local status=...` fails with
        # "read-only variable: status"). Every function in this plan that
        # holds a per-finding status string uses status_val for the same
        # reason.
        local status_val="${AUDIT_STATUS[$i]}" severity="${AUDIT_SEVERITY[$i]}"

        case "$status_val" in
            PASS) pass_count=$((pass_count + 1)) ;;
            FAIL) fail_count=$((fail_count + 1)) ;;
            WARN) warn_count=$((warn_count + 1)) ;;
            INFO) info_count=$((info_count + 1)) ;;
        esac

        if [[ "$status_val" == "INFO" ]]; then
            continue
        fi

        local weight="${severity_weight[$severity]:-0}"
        if [[ "$weight" -eq 0 ]]; then
            continue
        fi

        max_points=$(( max_points + weight ))
        case "$status_val" in
            PASS) earned_points=$(( earned_points + weight )) ;;
            WARN) earned_points=$(( earned_points + weight * 0.5 )) ;;
            FAIL) ;;
        esac

        if [[ "$status_val" == "FAIL" && "$severity" == "Critical" ]]; then
            critical_fails=$((critical_fails + 1))
        fi
        if [[ "$status_val" == "FAIL" && "$severity" == "High" ]]; then
            high_fails=$((high_fails + 1))
        fi
    done

    local score="100.0"
    if (( max_points > 0 )); then
        score=$(printf '%.1f' "$(( (earned_points / max_points) * 100 ))")
    fi

    local risk
    if (( critical_fails >= 1 )); then
        risk="CRITICAL"
    elif (( high_fails >= 3 )) || (( ${score} < 60 )); then
        risk="HIGH"
    elif (( ${score} < 80 )); then
        risk="MEDIUM"
    else
        risk="LOW"
    fi

    POSTURE_SCORE="$score"
    POSTURE_RISK="$risk"
    POSTURE_TOTAL="$total"
    POSTURE_PASS="$pass_count"
    POSTURE_FAIL="$fail_count"
    POSTURE_WARN="$warn_count"
    POSTURE_INFO="$info_count"
    POSTURE_CRITICAL_FAILS="$critical_fails"
    POSTURE_HIGH_FAILS="$high_fails"
}

# ---- 91-report-html.zsh ----
#
# HTML dashboard generation.

html_escape() {
    local s="$1"
    s="${s//&/&amp;}"
    s="${s//</&lt;}"
    s="${s//>/&gt;}"
    s="${s//\"/&quot;}"
    s="${s//\'/&#39;}"
    print -r -- "$s"
}

html_set_token() {
    # zsh has no bash-style "local -n"/"typeset -n" nameref (confirmed
    # live: zsh 5.9 rejects "-n" outright) — indirect assignment goes
    # through eval instead. Only the variable NAME ($1, always a
    # hardcoded literal like "html" at every call site) is spliced into
    # the eval'd code; $token and $value are referenced by name inside
    # it and resolved through normal variable lookup, not string-spliced,
    # so arbitrary content in either is never interpreted as code.
    local var_name="$1"
    local token="$2" value="$3"
    eval "${var_name}=\${${var_name}//\$token/\$value}"
}

get_system_information_summary() {
    SYS_COMPUTERNAME="$COMPUTER_NAME"
    SYS_DOMAIN="Unknown"
    SYS_MODEL="Unknown"
    SYS_CHIP="Unknown"
    SYS_RAM="Unknown"
    SYS_UPTIME="Unknown"
    SYS_LASTBOOT="Unknown"
    SYS_CURRENTUSER="Unknown"
    SYS_IP="Unknown"
    SYS_DISK="Unknown"
    SYS_APPCOUNT="Unknown"
    SYS_FILEVAULT="Unknown"
    SYS_SIP="Unknown"
    SYS_MDM="Unknown"

    run_root system_profiler SPHardwareDataType
    local hw_output="$ROOT_CMD_OUTPUT"
    local model chip ram
    model=$(print -r -- "$hw_output" | awk -F': ' '/Model Name/{print $2; exit}')
    chip=$(print -r -- "$hw_output" | awk -F': ' '/^ *Chip:|Processor Name/{print $2; exit}')
    ram=$(print -r -- "$hw_output" | awk -F': ' '/Memory:/{print $2; exit}')
    [[ -n "$model" ]] && SYS_MODEL="$model"
    [[ -n "$chip" ]] && SYS_CHIP="$chip"
    [[ -n "$ram" ]] && SYS_RAM="$ram"

    run_root sw_vers
    local osinfo
    osinfo=$(print -r -- "$ROOT_CMD_OUTPUT" | tr '\n' ' ')
    [[ -n "$osinfo" ]] && SYS_OSVERSION="$osinfo"

    run_root sysctl -n kern.boottime
    local boot_epoch
    # Anchored on "{ sec = " specifically: a plain ".*sec = ([0-9]+).*"
    # pattern is greedy, so it matches the LAST "sec = <digits>"
    # substring in the string — which also matches inside "usec = 0"
    # (u-SEC) — silently corrupting the parse to epoch-adjacent garbage
    # instead of the real boot time. Confirmed live with sed before
    # writing this (same bug independently found in the Domain 30
    # inventory check's boottime parsing).
    boot_epoch=$(print -r -- "$ROOT_CMD_OUTPUT" | sed -E 's/.*\{ sec = ([0-9]+).*/\1/')
    if [[ "$boot_epoch" == <-> ]]; then
        SYS_LASTBOOT=$(date -r "$boot_epoch" '+%Y-%m-%d %H:%M:%S')
        local now_epoch=$(date +%s)
        local uptime_secs=$(( now_epoch - boot_epoch ))
        local up_days=$(( uptime_secs / 86400 ))
        local up_hours=$(( (uptime_secs % 86400) / 3600 ))
        SYS_UPTIME="${up_days}d ${up_hours}h"
    fi

    [[ -n "$CONSOLE_USER" ]] && SYS_CURRENTUSER="$CONSOLE_USER (console session)"

    run_root ipconfig getifaddr en0
    if [[ "$ROOT_CMD_STATUS" -eq 0 && -n "$ROOT_CMD_OUTPUT" ]]; then
        SYS_IP="$ROOT_CMD_OUTPUT"
    else
        SYS_IP="No active en0 IPv4 address found"
    fi

    run_root df -H /
    local disk_line
    disk_line=$(print -r -- "$ROOT_CMD_OUTPUT" | awk 'NR==2')
    [[ -n "$disk_line" ]] && SYS_DISK="$disk_line"

    run_root find /Applications -maxdepth 1 -name '*.app'
    SYS_APPCOUNT=$(print -r -- "$ROOT_CMD_OUTPUT" | grep -c '\.app$')

    run_root fdesetup status
    if [[ "$ROOT_CMD_OUTPUT" == *"FileVault is On"* ]]; then
        SYS_FILEVAULT="On"
    elif [[ "$ROOT_CMD_OUTPUT" == *"FileVault is Off"* ]]; then
        SYS_FILEVAULT="Off"
    fi

    run_root csrutil status
    if [[ "$ROOT_CMD_OUTPUT" == *"disabled"* ]]; then
        SYS_SIP="Disabled"
    elif [[ "$ROOT_CMD_OUTPUT" == *"enabled"* ]]; then
        SYS_SIP="Enabled"
    fi

    run_root profiles status -type enrollment
    if [[ "$ROOT_CMD_OUTPUT" == *"MDM enrollment: Yes"* ]]; then
        SYS_MDM="Enrolled"
    elif [[ "$ROOT_CMD_OUTPUT" == *"MDM enrollment: No"* ]]; then
        SYS_MDM="Not enrolled"
    fi
}

_findings_table_rows() {
    local rows="" i total="${#AUDIT_STATUS[@]}"
    for (( i = 1; i <= total; i++ )); do
        # Named status_val, not status: zsh's `status` is a read-only alias
        # for `$?` — `local status=...` fails with "read-only variable:
        # status" (verified with `zsh -c` during planning).
        local status_val="${AUDIT_STATUS[$i]}" severity="${AUDIT_SEVERITY[$i]}"
        # Every name below is initialized with ="" (never bare "local x"):
        # zsh's `local`/`typeset`, re-run on a name that already has a
        # value from a previous loop iteration, PRINTS "name=value" to
        # stdout instead of declaring it (confirmed live with `zsh -c`) —
        # this is exactly what corrupted a real 99-finding report's
        # <tbody> with visible "control_esc='...' category_esc='...'"
        # text instead of table rows.
        local control_esc="" category_esc="" current_esc="" details_esc="" recommended_esc="" recommendation_esc=""
        control_esc=$(html_escape "${AUDIT_CONTROL[$i]}")
        category_esc=$(html_escape "${AUDIT_CATEGORY[$i]}")
        current_esc=$(html_escape "${AUDIT_CURRENT[$i]}")
        details_esc=$(html_escape "${AUDIT_DETAILS[$i]}")
        recommended_esc=$(html_escape "${AUDIT_RECOMMENDED[$i]}")
        recommendation_esc=$(html_escape "${AUDIT_RECOMMENDATION[$i]}")

        # A finding with a --details list gets its Measured value wrapped
        # in a hover target instead of shown as plain text — the full
        # item list (every installed app, every listening port, every
        # admin group member, ...) lives in data-tooltip and is
        # positioned by the page's own JS on hover, never inline in the
        # table, so a 35-item list doesn't blow out row height.
        local measured_value="$current_esc"
        if [[ -n "$details_esc" ]]; then
            measured_value="<span class=\"has-tooltip\" data-tooltip=\"$details_esc\">$current_esc</span>"
        fi
        local search_blob=""
        search_blob=$(html_escape "$(print -r -- "${AUDIT_CONTROL[$i]} ${AUDIT_CATEGORY[$i]} ${AUDIT_RECOMMENDATION[$i]}" | tr '[:upper:]' '[:lower:]')")
        local status_class="status-${status_val:l}" severity_class="sev-${severity:l}"

        local chips="" cd=""
        local -a chip_defs
        chip_defs=(
            "CIS:${AUDIT_CIS[$i]}" "NIST:${AUDIT_NIST[$i]}" "MITRE:${AUDIT_MITRE[$i]}"
            "ISO27001:${AUDIT_ISO27001[$i]}" "NIS2:${AUDIT_NIS2[$i]}" "NSA:${AUDIT_NSA[$i]}"
            "CIS-macOS:${AUDIT_CISMACOS[$i]}" "mSCP:${AUDIT_MSCP[$i]}"
        )
        for cd in "${chip_defs[@]}"; do
            local label="${cd%%:*}" val="${cd#*:}"
            if [[ -n "$val" && "$val" != "N/A" ]]; then
                chips+="<span class=\"fw-chip\"><b>$(html_escape "$label")</b>$(html_escape "$val")</span>"
            fi
        done
        [[ -z "$chips" ]] && chips='<span class="fw-chip fw-chip-empty">N/A</span>'

        rows+="<tr class=\"finding-row\" data-status=\"$status_val\" data-severity=\"$severity\" data-category=\"$category_esc\" data-search=\"$search_blob\">"
        rows+="<td class=\"col-control\"><strong>$control_esc</strong><div class=\"cell-sub\">$category_esc</div></td>"
        rows+="<td class=\"col-status\"><span class=\"badge $status_class\">$status_val</span></td>"
        rows+="<td class=\"col-severity\"><span class=\"badge $severity_class\">$severity</span></td>"
        rows+="<td class=\"col-value\"><div class=\"mv-block\"><div class=\"mv-label\">Measured</div><div class=\"mv-content\">$measured_value</div></div><div class=\"mv-divider\"></div><div class=\"mv-block\"><div class=\"mv-label\">Expected</div><div class=\"mv-content mv-expected\">$recommended_esc</div></div></td>"
        rows+="<td class=\"col-frameworks\"><div class=\"fw-chips\">$chips</div></td>"
        rows+="<td class=\"col-remediation\">$recommendation_esc</td>"
        rows+="</tr>"
    done
    print -r -- "$rows"
}

get_html_template() {
    cat <<'HTMLTEMPLATE_EOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>EndpointPostureCheck - {{COMPUTERNAME}}</title>
<style>
  :root {
    --bg: #0b1220; --panel: #121b2e; --panel-alt: #17233a; --border: #24324d;
    --text: #e6ecf5; --text-muted: #93a2bd; --accent: #3b9dff;
    --green: #33c481; --red: #ff5c72; --amber: #ffb84d;
    --crit: #ff3b5c; --high: #ff7a45; --med: #ffc043; --low: #5b9dff; --info-sev: #8a97ad;
    --radius: 10px;
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; font-size: 14px; }
  .wrap { max-width: 1400px; margin: 0 auto; padding: 24px 20px 60px; }
  header.brand { display: flex; align-items: center; justify-content: space-between; padding: 18px 24px; background: var(--panel); border: 1px solid var(--border); border-radius: var(--radius); margin-bottom: 20px; flex-wrap: wrap; gap: 12px; }
  .brand-title h1 { margin: 0; font-size: 19px; }
  .brand-title .sub { color: var(--text-muted); font-size: 12.5px; }
  .brand-meta { text-align: right; font-size: 12.5px; color: var(--text-muted); }
  .brand-meta strong { color: var(--text); }
  .sysinfo-panel { margin-bottom: 20px; background: var(--panel); border: 1px solid var(--border); border-radius: var(--radius); padding: 16px; }
  .sysinfo-panel .panel-title { margin: 0 0 12px 0; font-size: 13px; font-weight: 700; text-transform: uppercase; color: var(--text-muted); }
  .sysinfo-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px 20px; }
  @media (max-width: 900px) { .sysinfo-grid { grid-template-columns: repeat(2, 1fr); } }
  @media (max-width: 520px) { .sysinfo-grid { grid-template-columns: 1fr; } }
  .sysinfo-label { color: var(--text-muted); font-size: 11px; text-transform: uppercase; margin-bottom: 3px; }
  .sysinfo-value { font-size: 13.5px; font-weight: 600; word-break: break-word; }
  .summary-grid { display: grid; grid-template-columns: 200px repeat(5, 1fr); gap: 16px; margin-bottom: 22px; }
  @media (max-width: 1100px) { .summary-grid { grid-template-columns: 1fr 1fr 1fr; } }
  @media (max-width: 640px) { .summary-grid { grid-template-columns: 1fr 1fr; } }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: var(--radius); padding: 16px; }
  .score-card { display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 10px; }
  .score-ring { width: 130px; height: 130px; border-radius: 50%; background: conic-gradient(var(--accent) {{SCORE_DEG}}deg, #24324d 0deg); display: flex; align-items: center; justify-content: center; position: relative; }
  .score-ring::before { content: ""; position: absolute; width: 100px; height: 100px; border-radius: 50%; background: var(--panel); }
  .score-ring .score-value { position: relative; z-index: 1; font-size: 26px; font-weight: 800; }
  .score-ring .score-value small { display: block; font-size: 11px; color: var(--text-muted); font-weight: 500; }
  .risk-pill { display: inline-block; padding: 4px 14px; border-radius: 999px; font-weight: 700; font-size: 12px; }
  .risk-low { background: rgba(51,196,129,0.18); color: var(--green); border: 1px solid var(--green); }
  .risk-medium { background: rgba(255,192,67,0.18); color: var(--amber); border: 1px solid var(--amber); }
  .risk-high { background: rgba(255,122,69,0.18); color: var(--high); border: 1px solid var(--high); }
  .risk-critical { background: rgba(255,59,92,0.18); color: var(--crit); border: 1px solid var(--crit); }
  .stat-card { display: flex; flex-direction: column; justify-content: center; gap: 4px; }
  .stat-card .stat-num { font-size: 28px; font-weight: 800; }
  .stat-card .stat-label { color: var(--text-muted); font-size: 12px; text-transform: uppercase; }
  .stat-pass .stat-num { color: var(--green); }
  .stat-fail .stat-num { color: var(--red); }
  .stat-warn .stat-num { color: var(--amber); }
  .stat-info .stat-num { color: var(--accent); }
  .controls { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; background: var(--panel); border: 1px solid var(--border); border-radius: var(--radius); padding: 14px 16px; margin-bottom: 16px; }
  .controls .filter-btn { background: var(--panel-alt); border: 1px solid var(--border); color: var(--text); padding: 7px 14px; border-radius: 999px; cursor: pointer; font-size: 12.5px; font-weight: 600; }
  .controls .filter-btn.active { background: rgba(59,157,255,0.15); border-color: var(--accent); color: var(--accent); }
  .controls select, .controls input[type="text"] { background: var(--panel-alt); border: 1px solid var(--border); color: var(--text); padding: 7px 12px; border-radius: 6px; font-size: 12.5px; }
  .controls input[type="text"] { min-width: 220px; }
  .controls .spacer { flex: 1; }
  .controls .result-count { color: var(--text-muted); font-size: 12.5px; }
  /* table-layout: fixed makes the column-width percentages below
     authoritative instead of advisory — without it, a browser expands
     columns to fit unbroken content (a long remediation sentence, a
     stat like the Disk value) regardless of the % set, which is what
     pushed the real table past the viewport and forced a horizontal
     scroll to reach Frameworks/Remediation even on a normal-width
     desktop window. Every column below carries a matching width on both
     its <th> and <td> (fixed layout takes column widths from the first
     row that specifies them, so header-only or body-only widths are
     unreliable) and word-break so long text wraps within its column
     instead of forcing it wider. */
  table { width: 100%; min-width: 700px; table-layout: fixed; border-collapse: collapse; background: var(--panel); border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; }
  thead th { text-align: left; font-size: 11px; text-transform: uppercase; color: var(--text-muted); background: var(--panel-alt); padding: 12px 14px; border-bottom: 1px solid var(--border); position: sticky; top: 0; }
  tbody td { padding: 12px 14px; border-bottom: 1px solid var(--border); vertical-align: top; word-break: break-word; overflow-wrap: anywhere; }
  .col-control { width: 15%; } .col-status { width: 8%; } .col-severity { width: 9%; } .col-value { width: 24%; } .col-frameworks { width: 20%; } .col-remediation { width: 24%; }
  .cell-sub { color: var(--text-muted); font-size: 11.5px; margin-top: 2px; }
  .badge { display: inline-block; padding: 3px 9px; border-radius: 6px; font-size: 11px; font-weight: 700; }
  .status-pass { background: rgba(51,196,129,0.15); color: var(--green); }
  .status-fail { background: rgba(255,92,114,0.15); color: var(--red); }
  .status-warn { background: rgba(255,184,77,0.15); color: var(--amber); }
  .status-info { background: rgba(59,157,255,0.15); color: var(--accent); }
  .sev-critical { background: rgba(255,59,92,0.15); color: var(--crit); }
  .sev-high { background: rgba(255,122,69,0.15); color: var(--high); }
  .sev-medium { background: rgba(255,192,67,0.15); color: var(--med); }
  .sev-low { background: rgba(91,157,255,0.15); color: var(--low); }
  .sev-informational { background: rgba(138,151,173,0.15); color: var(--info-sev); }
  .mv-block { margin-bottom: 6px; } .mv-label { color: var(--text-muted); font-size: 10.5px; text-transform: uppercase; }
  .mv-divider { height: 1px; background: var(--border); margin: 6px 0; }
  .fw-chips { display: flex; flex-wrap: wrap; gap: 4px; }
  .fw-chip { background: var(--panel-alt); border: 1px solid var(--border); border-radius: 5px; padding: 2px 6px; font-size: 10.5px; color: var(--text-muted); }
  .fw-chip b { color: var(--text); margin-right: 3px; }
  .fw-chip-empty { opacity: 0.5; }
  .has-tooltip { cursor: help; border-bottom: 1px dotted var(--text-muted); }
  .ep-tooltip { position: absolute; z-index: 50; max-width: 360px; background: var(--panel-alt); border: 1px solid var(--border); border-radius: 8px; padding: 10px 12px; font-size: 12px; line-height: 1.6; color: var(--text); box-shadow: 0 8px 24px rgba(0,0,0,0.45); word-break: break-word; white-space: pre-line; }
  [hidden] { display: none !important; }
  footer.credit { text-align: center; color: var(--text-muted); font-size: 11.5px; margin-top: 20px; }
</style>
</head>
<body>
<div class="wrap">
  <header class="brand">
    <div class="brand-title">
      <h1>EndpointPostureCheck</h1>
      <div class="sub">macOS Security Posture Audit</div>
    </div>
    <div class="brand-meta">
      <div><strong>{{COMPUTERNAME}}</strong></div>
      <div>{{OSINFO}}</div>
      <div>Generated {{TIMESTAMP}} &middot; v{{VERSION}}</div>
    </div>
  </header>

  <div class="sysinfo-panel">
    <div class="panel-title">System Overview</div>
    <div class="sysinfo-grid">
      <div><div class="sysinfo-label">Model / Chip</div><div class="sysinfo-value">{{SYS_MODEL}} &middot; {{SYS_CHIP}}</div></div>
      <div><div class="sysinfo-label">Memory</div><div class="sysinfo-value">{{SYS_RAM}}</div></div>
      <div><div class="sysinfo-label">Uptime</div><div class="sysinfo-value">{{SYS_UPTIME}}</div></div>
      <div><div class="sysinfo-label">Last Boot</div><div class="sysinfo-value">{{SYS_LASTBOOT}}</div></div>
      <div><div class="sysinfo-label">Console User</div><div class="sysinfo-value">{{SYS_CURRENTUSER}}</div></div>
      <div><div class="sysinfo-label">IP Address</div><div class="sysinfo-value">{{SYS_IP}}</div></div>
      <div><div class="sysinfo-label">Disk (Root Volume)</div><div class="sysinfo-value">{{SYS_DISK}}</div></div>
      <div><div class="sysinfo-label">Installed Applications</div><div class="sysinfo-value">{{SYS_APPCOUNT}}</div></div>
      <div><div class="sysinfo-label">FileVault</div><div class="sysinfo-value">{{SYS_FILEVAULT}}</div></div>
      <div><div class="sysinfo-label">System Integrity Protection</div><div class="sysinfo-value">{{SYS_SIP}}</div></div>
      <div><div class="sysinfo-label">MDM Enrollment</div><div class="sysinfo-value">{{SYS_MDM}}</div></div>
    </div>
  </div>

  <div class="summary-grid">
    <div class="card score-card">
      <div class="score-ring"><div class="score-value">{{SCORE}}%<small>Compliance</small></div></div>
      <div class="risk-pill {{RISK_CLASS}}">{{RISK_LEVEL}}</div>
    </div>
    <div class="card stat-card"><div class="stat-num">{{TOTAL}}</div><div class="stat-label">Total Controls</div></div>
    <div class="card stat-card stat-pass"><div class="stat-num">{{PASS_COUNT}}</div><div class="stat-label">Pass</div></div>
    <div class="card stat-card stat-fail"><div class="stat-num">{{FAIL_COUNT}}</div><div class="stat-label">Fail</div></div>
    <div class="card stat-card stat-warn"><div class="stat-num">{{WARN_COUNT}}</div><div class="stat-label">Warn</div></div>
    <div class="card stat-card stat-info"><div class="stat-num">{{INFO_COUNT}}</div><div class="stat-label">Info</div></div>
  </div>

  <div class="controls">
    <button type="button" class="filter-btn active" data-filter="all">All</button>
    <button type="button" class="filter-btn" data-filter="fail">Failures Only</button>
    <button type="button" class="filter-btn" data-filter="warn">Warnings Only</button>
    <button type="button" class="filter-btn" data-filter="crithigh">Critical/High Only</button>
    <select id="categoryFilter"><option value="">All Categories</option>{{CATEGORY_OPTIONS}}</select>
    <input type="text" id="searchInput" placeholder="Search controls, categories, remediation...">
    <div class="spacer"></div>
    <div class="result-count" id="resultCount"></div>
  </div>

  <div style="overflow-x:auto;">
    <table>
      <thead>
        <tr>
          <th class="col-control">Control</th>
          <th class="col-status">Status</th>
          <th class="col-severity">Severity</th>
          <th class="col-value">Measured / Expected</th>
          <th class="col-frameworks">Frameworks</th>
          <th class="col-remediation">Remediation</th>
        </tr>
      </thead>
      <tbody id="findingsBody">
        {{TABLE_ROWS}}
      </tbody>
    </table>
  </div>

  <footer class="credit">EndpointPostureCheck for macOS &middot; read-only audit, no system changes made</footer>
</div>

<script>
(function () {
  var rows = Array.prototype.slice.call(document.querySelectorAll('.finding-row'));
  var statusFilter = 'all';
  var categoryFilter = '';
  var searchTerm = '';

  function applyFilters() {
    var visible = 0;
    rows.forEach(function (row) {
      var status = row.getAttribute('data-status');
      var severity = row.getAttribute('data-severity');
      var category = row.getAttribute('data-category');
      var search = row.getAttribute('data-search');

      var statusOk = true;
      if (statusFilter === 'fail') statusOk = status === 'FAIL';
      else if (statusFilter === 'warn') statusOk = status === 'WARN';
      else if (statusFilter === 'crithigh') statusOk = status === 'FAIL' && (severity === 'Critical' || severity === 'High');

      var categoryOk = categoryFilter === '' || category === categoryFilter;
      var searchOk = searchTerm === '' || search.indexOf(searchTerm) !== -1;

      var show = statusOk && categoryOk && searchOk;
      row.hidden = !show;
      if (show) visible++;
    });
    document.getElementById('resultCount').textContent = visible + ' of ' + rows.length + ' controls shown';
  }

  Array.prototype.slice.call(document.querySelectorAll('.filter-btn')).forEach(function (btn) {
    btn.addEventListener('click', function () {
      Array.prototype.slice.call(document.querySelectorAll('.filter-btn')).forEach(function (b) { b.classList.remove('active'); });
      btn.classList.add('active');
      statusFilter = btn.getAttribute('data-filter');
      applyFilters();
    });
  });

  document.getElementById('categoryFilter').addEventListener('change', function (e) {
    categoryFilter = e.target.value;
    applyFilters();
  });

  document.getElementById('searchInput').addEventListener('keyup', function (e) {
    searchTerm = e.target.value.toLowerCase();
    applyFilters();
  });

  applyFilters();
})();

(function () {
  // Portal-style tooltip: a single element appended to <body> and
  // positioned on hover via getBoundingClientRect, rather than an
  // absolutely-positioned child of the hovered cell — the table has
  // "overflow: hidden" for its own rounded corners, which would clip an
  // in-table tooltip anywhere near the table's edges.
  var tip = document.createElement('div');
  tip.className = 'ep-tooltip';
  tip.hidden = true;
  document.body.appendChild(tip);

  function showTip(el) {
    var text = el.getAttribute('data-tooltip');
    if (!text) return;
    tip.textContent = text;
    tip.hidden = false;
    var rect = el.getBoundingClientRect();
    var top = rect.bottom + window.scrollY + 6;
    var left = rect.left + window.scrollX;
    var maxLeft = window.scrollX + document.documentElement.clientWidth - tip.offsetWidth - 12;
    tip.style.top = top + 'px';
    tip.style.left = Math.max(12, Math.min(left, maxLeft)) + 'px';
  }
  function hideTip() { tip.hidden = true; }

  Array.prototype.slice.call(document.querySelectorAll('.has-tooltip')).forEach(function (el) {
    el.addEventListener('mouseenter', function () { showTip(el); });
    el.addEventListener('mouseleave', hideTip);
  });
})();
</script>
</body>
</html>
HTMLTEMPLATE_EOF
}

render_html_report() {
    local output_path="$1"
    get_system_information_summary

    local score_deg
    score_deg=$(printf '%.0f' "$(( (${POSTURE_SCORE} / 100) * 360 ))")
    local risk_class="risk-${POSTURE_RISK:l}"

    local category_options="" i total="${#AUDIT_CATEGORY[@]}"
    local -A category_seen
    for (( i = 1; i <= total; i++ )); do
        local cat="${AUDIT_CATEGORY[$i]}"
        if [[ -z "${category_seen[$cat]:-}" ]]; then
            category_seen[$cat]=1
            local cat_esc=""
            cat_esc=$(html_escape "$cat")
            category_options+="<option value=\"$cat_esc\">$cat_esc</option>"$'\n'
        fi
    done

    local table_rows
    table_rows=$(_findings_table_rows)

    local html
    html=$(get_html_template)

    html_set_token html '{{COMPUTERNAME}}' "$(html_escape "$SYS_COMPUTERNAME")"
    html_set_token html '{{OSINFO}}' "$(html_escape "${SYS_OSVERSION:-Unknown}")"
    html_set_token html '{{TIMESTAMP}}' "$(date '+%Y-%m-%d %H:%M:%S')"
    html_set_token html '{{VERSION}}' "$SCRIPT_VERSION"
    html_set_token html '{{SCORE}}' "$POSTURE_SCORE"
    html_set_token html '{{SCORE_DEG}}' "$score_deg"
    html_set_token html '{{RISK_LEVEL}}' "$POSTURE_RISK"
    html_set_token html '{{RISK_CLASS}}' "$risk_class"
    html_set_token html '{{TOTAL}}' "$POSTURE_TOTAL"
    html_set_token html '{{PASS_COUNT}}' "$POSTURE_PASS"
    html_set_token html '{{FAIL_COUNT}}' "$POSTURE_FAIL"
    html_set_token html '{{WARN_COUNT}}' "$POSTURE_WARN"
    html_set_token html '{{INFO_COUNT}}' "$POSTURE_INFO"
    html_set_token html '{{CATEGORY_OPTIONS}}' "$category_options"
    html_set_token html '{{TABLE_ROWS}}' "$table_rows"
    html_set_token html '{{SYS_MODEL}}' "$(html_escape "$SYS_MODEL")"
    html_set_token html '{{SYS_CHIP}}' "$(html_escape "$SYS_CHIP")"
    html_set_token html '{{SYS_RAM}}' "$(html_escape "$SYS_RAM")"
    html_set_token html '{{SYS_UPTIME}}' "$(html_escape "$SYS_UPTIME")"
    html_set_token html '{{SYS_LASTBOOT}}' "$(html_escape "$SYS_LASTBOOT")"
    html_set_token html '{{SYS_CURRENTUSER}}' "$(html_escape "$SYS_CURRENTUSER")"
    html_set_token html '{{SYS_IP}}' "$(html_escape "$SYS_IP")"
    html_set_token html '{{SYS_DISK}}' "$(html_escape "$SYS_DISK")"
    html_set_token html '{{SYS_APPCOUNT}}' "$SYS_APPCOUNT"
    html_set_token html '{{SYS_FILEVAULT}}' "$(html_escape "$SYS_FILEVAULT")"
    html_set_token html '{{SYS_SIP}}' "$(html_escape "$SYS_SIP")"
    html_set_token html '{{SYS_MDM}}' "$(html_escape "$SYS_MDM")"

    print -r -- "$html" > "$output_path"
}

# ---- 92-report-json.zsh ----
#
# JSON export.

json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\t'/\\t}"
    s="${s//$'\r'/\\r}"
    print -r -- "$s"
}

export_json_report() {
    local output_path="$1"

    run_root sw_vers
    local osinfo
    osinfo=$(print -r -- "$ROOT_CMD_OUTPUT" | tr '\n' ' ')
    [[ -z "$osinfo" ]] && osinfo="Unknown"

    local i total="${#AUDIT_STATUS[@]}"
    local findings_json=""
    for (( i = 1; i <= total; i++ )); do
        [[ $i -gt 1 ]] && findings_json+=","
        findings_json+=$(cat <<EOF
{"Id":${AUDIT_IDS[$i]},"Category":"$(json_escape "${AUDIT_CATEGORY[$i]}")","Control":"$(json_escape "${AUDIT_CONTROL[$i]}")","Status":"${AUDIT_STATUS[$i]}","Severity":"${AUDIT_SEVERITY[$i]}","CurrentValue":"$(json_escape "${AUDIT_CURRENT[$i]}")","Details":"$(json_escape "${AUDIT_DETAILS[$i]}")","RecommendedValue":"$(json_escape "${AUDIT_RECOMMENDED[$i]}")","CIS_Control":"$(json_escape "${AUDIT_CIS[$i]}")","NIST_Control":"$(json_escape "${AUDIT_NIST[$i]}")","MITRE_Technique":"$(json_escape "${AUDIT_MITRE[$i]}")","ISO27001_Control":"$(json_escape "${AUDIT_ISO27001[$i]}")","NIS2_Article":"$(json_escape "${AUDIT_NIS2[$i]}")","NSA_Guidance":"$(json_escape "${AUDIT_NSA[$i]}")","CIS_macOS_Control":"$(json_escape "${AUDIT_CISMACOS[$i]}")","mSCP_Rule":"$(json_escape "${AUDIT_MSCP[$i]}")","Recommendation":"$(json_escape "${AUDIT_RECOMMENDATION[$i]}")","Timestamp":"${AUDIT_TIMESTAMP[$i]}"}
EOF
)
    done

    cat > "$output_path" <<EOF
{
  "ToolName": "EndpointPostureCheck",
  "ToolVersion": "$SCRIPT_VERSION",
  "ComputerName": "$(json_escape "$COMPUTER_NAME")",
  "OperatingSystem": "$(json_escape "$osinfo")",
  "ScanStartTime": "$START_TIME_HUMAN",
  "ScanEndTime": "$(date '+%Y-%m-%d %H:%M:%S')",
  "ComplianceScore": $POSTURE_SCORE,
  "RiskLevel": "$POSTURE_RISK",
  "Summary": {
    "TotalControls": $POSTURE_TOTAL,
    "Pass": $POSTURE_PASS,
    "Fail": $POSTURE_FAIL,
    "Warn": $POSTURE_WARN,
    "Info": $POSTURE_INFO,
    "CriticalFails": $POSTURE_CRITICAL_FAILS,
    "HighFails": $POSTURE_HIGH_FAILS
  },
  "Findings": [$findings_json]
}
EOF
}

# ---- 93-remediation.zsh ----
#
# Remediation script generator.

_shell_single_quote_escape() {
    local s="$1"
    print -r -- "${s//\'/'\\''}"
}

get_remediation_snippet() {
    local key="$1"
    case "$key" in
        os_gatekeeper_enable)
            print -r -- 'sudo spctl --master-enable'
            ;;
        os_filevault_enable)
            cat <<'EOF'
echo "FileVault needs an interactive prompt or a pre-generated institutional recovery key; it cannot be silently enabled unattended."
echo "Run interactively: sudo fdesetup enable"
EOF
            ;;
        os_root_disable)
            print -r -- "sudo dscl . -create /Users/root Password '*'"
            ;;
        os_guest_account_disable)
            print -r -- 'sudo defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false'
            ;;
        os_firewall_enable)
            print -r -- 'sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on'
            ;;
        os_sshd_permit_root_login_disable)
            cat <<'EOF'
sudo cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.bak.$(date +%Y%m%d%H%M%S)"
sudo sed -i '' -E 's/^#?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
echo "sshd_config updated. Restart sshd (or reboot) for the change to take effect."
EOF
            ;;
        os_screensaver_password_enforce)
            print -r -- 'sudo -u "$CONSOLE_USER" defaults write com.apple.screensaver askForPassword -bool true'
            ;;
        os_autologin_disable)
            print -r -- 'sudo defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser'
            ;;
        os_dyld_insert_libraries_unset)
            print -r -- 'sudo launchctl unsetenv DYLD_INSERT_LIBRARIES'
            ;;
        # --- CIS Apple macOS 26 Tahoe additions. Only single-setting,
        # reversible fixes are automated; password policy, sudoers,
        # permission and folder-removal findings stay manual-review. ---
        system_settings_printer_sharing_disable)
            print -r -- 'sudo cupsctl --no-share-printers'
            ;;
        system_settings_rae_disable)
            print -r -- 'sudo systemsetup -setremoteappleevents off'
            ;;
        system_settings_guest_access_smb_disable)
            print -r -- 'sudo sysadminctl -smbGuestAccess off'
            ;;
        system_settings_time_server_enforce)
            print -r -- 'sudo systemsetup -setusingnetworktime on'
            ;;
        os_time_server_enabled)
            print -r -- 'sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.timed.plist'
            ;;
        system_settings_password_hints_disable)
            print -r -- 'sudo defaults write /Library/Preferences/com.apple.loginwindow RetriesUntilHint -int 0'
            ;;
        system_settings_wake_network_access_disable)
            print -r -- 'sudo pmset -a womp 0'
            ;;
        os_power_nap_disable)
            print -r -- 'sudo pmset -a powernap 0'
            ;;
        os_httpd_disable)
            cat <<'EOF'
sudo launchctl disable system/org.apache.httpd
sudo launchctl bootout system/org.apache.httpd 2>/dev/null || true
EOF
            ;;
        os_nfsd_disable)
            cat <<'EOF'
sudo nfsd disable
[[ -e /etc/exports ]] && echo "Review and remove /etc/exports manually; it was left in place."
EOF
            ;;
        os_bonjour_disable)
            print -r -- 'sudo defaults write /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements -bool true'
            ;;
        os_unlock_active_user_session_disable)
            print -r -- 'sudo security authorizationdb write system.login.screensaver authenticate-session-owner'
            ;;
        *)
            print -r -- ''
            ;;
    esac
}

generate_remediation_script() {
    local output_path="$1"
    local i total="${#AUDIT_STATUS[@]}"
    local -a fail_indices
    for (( i = 1; i <= total; i++ )); do
        [[ "${AUDIT_STATUS[$i]}" == "FAIL" ]] && fail_indices+=("$i")
    done

    {
        echo '#!/usr/bin/env zsh'
        echo '#'
        echo '# Remediate-EndpointPostureCheck.sh - companion remediation script auto-generated'
        echo '# by Invoke-MacPostureCheck.sh.'
        echo "# Generated $(date '+%Y-%m-%d %H:%M:%S') for host $(_shell_single_quote_escape "$COMPUTER_NAME")."
        echo "# Contains one commented remediation block per FAIL finding from the audit run"
        echo "# (${#fail_indices[@]} finding(s)). Review every block BEFORE executing."
        echo '#'
        echo '# Usage:'
        echo '#   ./Remediate-EndpointPostureCheck.sh --dry-run   Preview every action, apply nothing (default).'
        echo '#   ./Remediate-EndpointPostureCheck.sh --force     Apply the actions.'
        echo ''
        echo 'set -u'
        echo 'DRY_RUN=1'
        echo 'for arg in "$@"; do'
        echo '    case "$arg" in'
        echo '        --force) DRY_RUN=0 ;;'
        echo '        --dry-run) DRY_RUN=1 ;;'
        echo '    esac'
        echo 'done'
        echo 'if [[ "$DRY_RUN" -eq 1 ]]; then'
        echo '    echo "Running in preview mode. Re-run with --force to apply changes."'
        echo 'fi'
        echo ''

        if [[ ${#fail_indices[@]} -eq 0 ]]; then
            echo 'echo "No FAIL findings were present in the source audit run - nothing to remediate."'
        else
            local idx
            for idx in "${fail_indices[@]}"; do
                echo "# --------------------------------------------------------------------------"
                echo "# Control      : ${AUDIT_CONTROL[$idx]}"
                echo "# Category     : ${AUDIT_CATEGORY[$idx]}"
                echo "# Severity     : ${AUDIT_SEVERITY[$idx]}"
                echo "# Current      : ${AUDIT_CURRENT[$idx]}"
                echo "# Expected     : ${AUDIT_RECOMMENDED[$idx]}"
                echo "# CIS-macOS    : ${AUDIT_CISMACOS[$idx]}"
                echo "# mSCP         : ${AUDIT_MSCP[$idx]}"
                echo "# Guidance     : ${AUDIT_RECOMMENDATION[$idx]}"
                echo "# --------------------------------------------------------------------------"

                local snippet="" control_esc="" reco_esc=""
                snippet=$(get_remediation_snippet "${AUDIT_MSCP[$idx]}")
                control_esc=$(_shell_single_quote_escape "${AUDIT_CONTROL[$idx]}")

                if [[ -n "$snippet" ]]; then
                    echo "if [[ \"\$DRY_RUN\" -eq 1 ]]; then"
                    echo "    echo 'Would remediate: $control_esc'"
                    echo "else"
                    print -r -- "$snippet" | sed 's/^/    /'
                    echo "fi"
                else
                    reco_esc=$(_shell_single_quote_escape "${AUDIT_RECOMMENDATION[$idx]}")
                    echo "echo 'MANUAL ACTION REQUIRED for \"$control_esc\": $reco_esc'"
                fi
                echo ''
            done
            echo 'echo "Remediation pass complete. Re-run Invoke-MacPostureCheck.sh to verify improved posture."'
        fi
    } > "$output_path"
    chmod +x "$output_path"
}

# ---- 99-main.zsh ----
#
# Main orchestration: version-support check, run every registered audit
# check, score, print summary, write reports.

_check_macos_version_support() {
    if ! macos_version_ge "15.0" "$OS_PRODUCT_VERSION"; then
        add_audit_result --category 'Audit Engine' --control 'macOS Version Support' \
            --status WARN --severity Low --current "$OS_PRODUCT_VERSION" \
            --recommended 'macOS 15 (Sequoia) or later' \
            --recommendation 'This macOS version is older than the tested baseline (15/26); results may be incomplete. The audit will continue.'
    fi
}

_run_all_checks() {
    local check_name
    for check_name in "${AUDIT_CHECKS[@]}"; do
        if ! functions "$check_name" >/dev/null 2>&1; then
            add_audit_result --category 'Audit Engine' --control "$check_name" \
                --status WARN --severity Low --current 'Check function not found' \
                --recommended 'Every registered check function exists' \
                --recommendation 'Internal error: this check was registered in 99-main.zsh but its function was not defined. Report this as a bug.'
            continue
        fi
        "$check_name"
    done
}

_print_audit_summary() {
    echo ''
    echo '================================================================================='
    echo ' AUDIT SUMMARY'
    echo '================================================================================='
    echo "  Compliance Score : ${POSTURE_SCORE}%"
    echo "  Risk Level       : $POSTURE_RISK"
    echo "  Total Controls   : $POSTURE_TOTAL"
    echo "  PASS / FAIL / WARN / INFO : $POSTURE_PASS / $POSTURE_FAIL / $POSTURE_WARN / $POSTURE_INFO"
    echo "  Critical Failures: $POSTURE_CRITICAL_FAILS   High-Severity Failures: $POSTURE_HIGH_FAILS"
    echo '================================================================================='
    echo ''
}

_resolve_output_paths() {
    local timestamp default_html_name default_json_name
    timestamp=$(date '+%Y%m%d_%H%M%S')
    default_html_name="EndpointPostureCheck_${COMPUTER_NAME}_${timestamp}.html"
    default_json_name="EndpointPostureCheck_${COMPUTER_NAME}_${timestamp}.json"

    if [[ -z "$REPORT_PATH" ]]; then
        HTML_OUTPUT_PATH="$(pwd)/$default_html_name"
        JSON_OUTPUT_PATH="$(pwd)/$default_json_name"
        REMEDIATION_OUTPUT_PATH="$(pwd)/Remediate-EndpointPostureCheck.sh"
    elif [[ -d "$REPORT_PATH" ]]; then
        HTML_OUTPUT_PATH="$REPORT_PATH/$default_html_name"
        JSON_OUTPUT_PATH="$REPORT_PATH/$default_json_name"
        REMEDIATION_OUTPUT_PATH="$REPORT_PATH/Remediate-EndpointPostureCheck.sh"
    else
        HTML_OUTPUT_PATH="$REPORT_PATH"
        local parent_dir
        parent_dir=$(dirname "$REPORT_PATH")
        [[ ! -d "$parent_dir" ]] && mkdir -p "$parent_dir"
        JSON_OUTPUT_PATH="$parent_dir/$default_json_name"
        REMEDIATION_OUTPUT_PATH="$parent_dir/Remediate-EndpointPostureCheck.sh"
    fi
}

main() {
    _check_macos_version_support

    echo ''
    echo '#################################################################################'
    echo '##                    E N D P O I N T P O S T U R E C H E C K                   ##'
    echo "##          macOS Security Posture Auditor  v$SCRIPT_VERSION"
    echo '#################################################################################'
    echo "Target Host : $COMPUTER_NAME"
    echo "Start Time  : $START_TIME_HUMAN"
    echo ''

    _run_all_checks

    get_compliance_posture
    _print_audit_summary

    _resolve_output_paths

    render_html_report "$HTML_OUTPUT_PATH"
    echo "[+] HTML dashboard written to : $HTML_OUTPUT_PATH"

    if [[ "$EXPORT_JSON" -eq 1 ]]; then
        export_json_report "$JSON_OUTPUT_PATH"
        echo "[+] JSON export written to     : $JSON_OUTPUT_PATH"
    fi

    if [[ "$GENERATE_REMEDIATION" -eq 1 ]]; then
        generate_remediation_script "$REMEDIATION_OUTPUT_PATH"
        echo "[+] Remediation script written : $REMEDIATION_OUTPUT_PATH"
    fi

    echo ''
    echo "EndpointPostureCheck completed in $(( $(date +%s) - START_TIME_EPOCH )) second(s)."
    echo ''
}

# --- Master check registry, grouped by domain in the same order as Tasks 3-33 ---
typeset -ga AUDIT_CHECKS
AUDIT_CHECKS=(
    # Domain 1: Hardware, Firmware & Platform Integrity
    check_secure_enclave_presence check_hardware_identification check_boot_rom_firmware_version
    # Domain 2: SIP & Kernel Security
    check_sip_status check_sip_custom_configuration check_third_party_system_extensions check_nvram_csr_override
    # Domain 3: Volume Encryption & Data-at-Rest (FileVault)
    check_filevault_status check_filevault_deferred_enablement check_filevault_enabled_user_count check_filevault_recovery_key_escrow
    # Domain 4: Gatekeeper, Notarization & Application Control
    check_gatekeeper_status check_quarantine_enforcement_telemetry check_applications_quarantine_flag_survey
    # Domain 5: Malware Defense (XProtect / MRT / EDR)
    check_xprotect_freshness check_mrt_freshness check_third_party_edr_presence check_endpoint_security_clients
    # Domain 6: TCC & Privacy Controls
    check_tcc_full_disk_access_grants check_tcc_screen_recording_grants check_tcc_accessibility_grants
    check_tcc_camera_microphone_grants check_tcc_database_permissions
    check_location_services_enabled check_location_services_menu_icon
    # Domain 7: Identity, Accounts & Privilege Management
    check_root_account_disabled check_guest_account_disabled check_admin_group_membership_inventory check_password_policy_configured
    check_sudoers_configuration
    check_password_lockout_threshold check_password_minimum_length check_password_age check_password_history
    check_sudo_timeout_zero check_sudo_timestamp_per_tty check_sudo_logging_enabled
    check_admin_password_for_system_preferences check_admin_cannot_unlock_other_sessions
    check_user_password_hints_absent check_smb_guest_access_disabled check_guest_home_folder_absent
    # Domain 8: Network Firewall & Packet Filtering
    check_firewall_state check_firewall_stealth_mode check_firewall_block_all_incoming check_firewall_signed_app_auto_allow
    check_firewall_per_app_exceptions check_etc_hosts_integrity
    # Domain 9: Remote Access & Sharing Services
    check_screen_sharing_state check_remote_management_state check_file_sharing_state check_remote_login_toggle
    check_airplay_receiver_disabled check_printer_sharing_disabled check_remote_apple_events_disabled
    check_internet_sharing_disabled check_content_caching_disabled check_media_sharing_disabled
    check_bluetooth_sharing_disabled
    # Domain 10: SSH Server & Client Hardening
    check_sshd_password_auth check_sshd_permit_root_login check_sshd_weak_ciphers check_ssh_client_strict_host_key_checking
    # Domain 11: Cryptography & Certificate Trust
    check_system_trust_settings_overrides check_login_keychain_lock_on_sleep check_fips_validated_crypto_note
    # Domain 12: Audit, Logging & Telemetry
    check_audit_subsystem_enabled check_audit_control_flags check_diagnostics_autosubmit check_unified_log_security_events
    check_network_time_enabled check_time_service_running check_install_log_retention check_audit_retention
    check_audit_records_access
    # Domain 13: Software Update & Patch Compliance
    check_recent_update_history check_auto_update_configuration check_rapid_security_response_state
    check_macos_updates_auto_install check_app_store_updates_auto_install check_security_responses_install_enabled
    check_software_update_deferral
    # Domain 14: MDM, Profiles & Supervision
    check_mdm_enrollment_and_supervision check_installed_profiles_inventory
    # Domain 15: Persistence Mechanisms & Auto-Runs
    check_system_launch_daemons_integrity check_system_launch_agents_integrity check_user_launch_agents_integrity check_login_items_inventory
    check_login_logout_hooks
    check_shell_startup_file_content check_shell_startup_file_permissions check_authorization_plugins
    check_directory_services_plugins check_privileged_helper_tools check_cron_and_at_jobs
    check_legacy_boot_and_periodic_scripts check_ssh_login_scripts check_ssh_authorized_keys_inventory
    check_python_startup_hooks check_btm_item_integrity check_autostart_inventory
    # Domain 16: Privilege Escalation - File & Directory Permissions
    check_writable_launchd_directories check_writable_path_directories check_suid_sgid_binary_audit
    check_home_folders_secure check_world_writable_applications check_world_writable_system_folder
    check_world_writable_library_folder
    # Domain 17: Dylib Hijacking & Code Injection
    check_dyld_insert_libraries_global_env check_writable_dylib_search_paths check_hardened_runtime_spotcheck
    # Domain 18: Credential Exposure & Secret Leaks
    check_ssh_private_key_permissions check_cloud_cli_credential_files check_shell_history_secret_sweep check_sensitive_filename_sweep
    # Domain 19: Screen Lock & Physical Access
    check_screensaver_password_required check_screensaver_grace_period check_auto_login_disabled check_login_window_hardening
    check_screen_saver_corners_secure check_screensaver_idle_time check_login_window_custom_message
    check_login_window_password_hints_disabled check_login_window_policy_banner
    # Domain 20: Removable Media & Peripheral Control
    check_usb_restriction_profile_presence check_thunderbolt_security_level
    # Domain 21: Wireless & Network Interface Security
    check_wifi_current_network_security check_bluetooth_power_state check_airdrop_discovery_scope check_network_interface_inventory
    # Domain 22: iCloud & Cloud Sync Surface
    check_icloud_keychain_sync_indicator check_activation_lock_status check_icloud_drive_sync_indicator
    check_icloud_desktop_documents_sync_disabled
    # Domain 23: Browser & Application Hardening
    check_safari_auto_open_safe_downloads check_safari_developer_menu_note check_safari_fraudulent_site_warning
    check_safari_cross_site_tracking_prevention check_safari_advertising_privacy_protection
    check_safari_show_full_website_address check_safari_show_status_bar check_terminal_secure_keyboard_entry
    # Domain 24: Ransomware Resilience & Recovery
    check_time_machine_configured_and_recent check_time_machine_encryption check_local_apfs_snapshots
    check_time_machine_auto_backup
    # Domain 25: Third-Party Software & Package Inventory
    check_installed_applications_inventory check_homebrew_prefix_permissions check_homebrew_package_inventory
    # Domain 26: System Services & Daemon Exposure
    check_listening_ports_inventory check_nonapple_running_launchd_services
    check_bonjour_advertising_disabled check_http_server_disabled check_nfs_server_disabled
    # Domain 27: Kernel & Boot Security
    check_boot_security_policy check_authenticated_root_status check_nvram_boot_args check_thirdparty_kext_inventory
    # Domain 28: Virtualization & Container Escape Surface
    check_docker_desktop_presence check_vm_hypervisor_apps_inventory
    # Domain 29: Data Loss Prevention & Sensitive Data
    check_screenshot_save_location_cloud_exposure check_handoff_universal_clipboard_note
    # Domain 31: Apple Intelligence, Siri & Analytics
    check_external_intelligence_disabled check_external_intelligence_sign_in_disabled check_writing_tools_disabled
    check_mail_summarization_disabled check_notes_transcription_disabled check_notes_summarization_disabled
    check_siri_disabled check_improve_siri_dictation_disabled check_improve_assistive_voice_disabled
    check_share_with_app_developers_disabled check_limit_ad_tracking_enabled check_help_apple_improve_search_disabled
    check_on_device_dictation_enforced
    # Domain 32: Power Management & Sleep
    check_sleep_enabled_apple_silicon check_power_nap_disabled_intel check_wake_for_network_access_disabled
    # Domain 30: System Inventory & Asset Information
    check_system_hardware_summary check_os_version_and_build check_disk_space_utilization
    check_installed_application_count check_uptime_and_last_boot
)

# Auto-invoke main() only when this file is the top-level executed script
# (true for the built single-file artifact), never when it's `source`d —
# e.g. by tests/test-main.zsh, which needs to call individual pieces under
# controlled stubs without triggering a full, unstubbed audit run.
# Verified empirically during planning: `${zsh_eval_context[-1]}` is
# "toplevel" when a file is executed directly, and ends in "file" (preceded
# by "cmdarg" or similar) when the same file is `source`d from elsewhere.
if [[ "${zsh_eval_context[-1]}" == "toplevel" ]]; then
    main "$@"
fi
