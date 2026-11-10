#!/usr/bin/env zsh
# EndpointPostureCheck for macOS — built 2026-11-10 20:46:30 from src/*.zsh. Do not edit directly.

# ---- 00-header.zsh ----
#
# EndpointPostureCheck for macOS
# A read-only security posture auditor for macOS 15/26 endpoints.
#
# Usage: Invoke-MacPostureCheck.sh [--report-path <dir|file>] [--export-json]
#                                   [--generate-remediation] [--generate-profile]
#                                   [--baseline <previous.json>] [--help]
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
GENERATE_PROFILE=0
BASELINE_PATH=""

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
  --generate-profile           Generate EndpointPostureCheck-Hardening.mobileconfig
                               with every profile-enforceable WARN/FAIL setting
                               (written for review only; never installed).
  --baseline <file.json>       Compare with an earlier --export-json report:
                               flags new autostart items, admins, permissions
                               and extensions, and lists what got worse/better.
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
        --generate-profile)
            GENERATE_PROFILE=1
            shift
            ;;
        --baseline)
            if [[ $# -lt 2 ]]; then
                echo "Error: --baseline requires a JSON file" >&2
                exit 1
            fi
            BASELINE_PATH="$2"
            shift 2
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
# A newline for use inside double-quoted expansions such as
# "${a}${b:+$NL$b}": $'\n' is not expanded inside double quotes and
# produced a literal "$'" in finding details.
typeset -g NL=$'\n'
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

# True when an octal mode string grants write to group or others ("664", "777", "1777").
_mode_group_or_other_writable() {
    local mode="$1"
    [[ "$mode" == <-> ]] || return 1
    local go="${mode[-2,-1]}"
    [[ "${go[1]}" == [2367] || "${go[2]}" == [2367] ]]
}

# Extended ACL entries (ls -lde) that let someone other than root, wheel, admin or the given
# expected owner write to a path. Mode bits alone miss these: a 0644 root-owned file with
# "user:bob allow write" is writable by bob. Prints one "principal: rights" line per grant;
# returns 1 when there are none. Deny entries are ignored (they only take rights away).
_acl_write_grantees() {
    local target="$1" expected_owner="${2:-root}" line="" principal="" rights="" r="" bad=""
    local -a out rlist
    local listing=""
    listing=$(command ls -lde -- "$target" 2>/dev/null) || return 1
    for line in "${(@f)listing}"; do
        [[ "$line" =~ '^ *[0-9]+: (.+) (allow|deny) ([a-z_,]+)$' ]] || continue
        [[ "${match[2]}" == allow ]] || continue
        principal="${match[1]% inherited}"; rights="${match[3]}"
        case "$principal" in
            user:root|group:wheel|group:admin|group:system|"user:$expected_owner") continue ;;
        esac
        bad=""
        rlist=(${(s:,:)rights})
        for r in "${rlist[@]}"; do
            case "$r" in
                write|append|add_file|add_subdirectory|delete_child|writeattr|writeextattr|writesecurity|chown)
                    bad+="${bad:+,}$r" ;;
            esac
        done
        [[ -n "$bad" ]] && out+=("$principal: $bad")
    done
    (( ${#out[@]} )) || return 1
    print -r -- "${(j:; :)out}"
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
            record_profile_fix "$suite" "$key" "${expect:-${max:-$min}}"
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
        record_profile_fix "$suite" "$key" "${expect:-${max:-$min}}"
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

    if [[ $mismatch -eq 1 || $found -ne ${#pairs[@]} ]]; then
        for pair in "${pairs[@]}"; do
            record_profile_fix com.apple.Safari "${pair%%=*}" "${pair#*=}"
        done
    fi
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

# Compliant values for every profile-enforceable setting that came out
# WARN or FAIL this run; 94-profile.zsh turns them into a .mobileconfig
# (--generate-profile). Parallel arrays, one entry per suite/key.
typeset -ga PROFILE_FIX_SUITES PROFILE_FIX_KEYS PROFILE_FIX_VALUES

record_profile_fix() {
    local suite="$1" key="$2" value="$3" i
    [[ -n "$suite" && -n "$key" && -n "$value" ]] || return 0
    for (( i = 1; i <= ${#PROFILE_FIX_KEYS[@]}; i++ )); do
        [[ "${PROFILE_FIX_SUITES[$i]}" == "$suite" && "${PROFILE_FIX_KEYS[$i]}" == "$key" ]] && return 0
    done
    PROFILE_FIX_SUITES+=("$suite"); PROFILE_FIX_KEYS+=("$key"); PROFILE_FIX_VALUES+=("$value")
}

# Background prefetch for slow, independent queries (sfltool dumpbtm,
# system_profiler SPAirPortDataType, the XProtect Remediator log): started
# at the beginning of main(), consumed by the check that needs it.
# run_prefetched falls back to running the command inline when nothing
# was prefetched (or the prefetch left no result), so checks behave the
# same when sourced alone in tests.
typeset -g PREFETCH_DIR=""
typeset -gA PREFETCH_PID

prefetch() {
    local name="$1"; shift
    if [[ -z "$PREFETCH_DIR" ]]; then
        PREFETCH_DIR=$(mktemp -d -t epc-prefetch) || return 0
    fi
    { "$@" > "$PREFETCH_DIR/$name.out" 2>&1; print -r -- $? > "$PREFETCH_DIR/$name.rc"; } &
    # Quoted on purpose: verified live that zsh leaves an unquoted $! in an
    # associative-element assignment unexpanded (stores the text "$!").
    PREFETCH_PID[$name]="$!"
}

# Waits for a prefetched result by polling for its .rc file while the
# background process is alive. A bug here once stored the literal text
# "$!" as the PID, `wait` returned at once, and the inline fallback
# started a second `sfltool dumpbtm` that hung beside the first.
# A prefetched command is therefore never re-run: a missing result or a
# timeout becomes a failed query (status 124) that the check reports as
# WARN. Only names that were never prefetched run inline.
: ${PREFETCH_TIMEOUT:=180}

run_prefetched() {
    local name="$1"; shift
    local pid="${PREFETCH_PID[$name]:-}" waited=0
    if [[ -z "$pid" ]]; then
        run_root "$@"
        return 0
    fi
    unset "PREFETCH_PID[$name]"
    while [[ ! -f "$PREFETCH_DIR/$name.rc" ]] && kill -0 "$pid" 2>/dev/null; do
        if (( waited >= PREFETCH_TIMEOUT * 5 )); then
            kill "$pid" 2>/dev/null
            pkill -P "$pid" 2>/dev/null
            break
        fi
        sleep 0.2
        waited=$((waited + 1))
    done
    if [[ -f "$PREFETCH_DIR/$name.rc" ]]; then
        ROOT_CMD_OUTPUT=$(< "$PREFETCH_DIR/$name.out")
        ROOT_CMD_STATUS=$(< "$PREFETCH_DIR/$name.rc")
    else
        ROOT_CMD_OUTPUT="background query '$*' did not finish within ${PREFETCH_TIMEOUT}s"
        ROOT_CMD_STATUS=124
    fi
    return 0
}

prefetch_cleanup() {
    local pid
    for pid in "${PREFETCH_PID[@]}"; do pkill -P "$pid" 2>/dev/null; kill "$pid" 2>/dev/null; done
    PREFETCH_PID=()
    [[ -n "$PREFETCH_DIR" && -d "$PREFETCH_DIR" ]] && command rm -rf "$PREFETCH_DIR"
    PREFETCH_DIR=""
}

# ---- 02-inventory.zsh ----
#
# Inventory tables: structured lists (processes, services, connections, firewall rules) that
# the dashboard shows as sortable, filterable tables and the JSON export carries as data.
# Inventories are never scored; checks that find something risky in them add a normal finding.
#
#   inventory_define <id> <title> <note> <column>...
#       column = "Label" or "Label:type" with type num | flags | path | ref=<tableId>.<Label>
#       (flags: comma-separated tags, a trailing "!" marks a bad tag, "?" a warning tag;
#        ref: the cell holds ", "-separated values that link to rows of another table)
#   inventory_add_row <id> <field>...

typeset -ga INV_ORDER=()
typeset -gA INV_TITLE=() INV_NOTE=() INV_COLS=() INV_ROWS=() INV_COUNT=()

INV_FS=$'\x1f'   # field separator inside a row / column list
INV_RS=$'\x1e'   # row separator

inventory_reset() {
    INV_ORDER=(); INV_TITLE=(); INV_NOTE=(); INV_COLS=(); INV_ROWS=(); INV_COUNT=()
}

inventory_define() {
    local id="$1" title="$2" note="$3"; shift 3
    (( ${INV_ORDER[(Ie)$id]} )) || INV_ORDER+=("$id")
    INV_TITLE[$id]="$title"; INV_NOTE[$id]="$note"
    INV_COLS[$id]="${(pj:\x1f:)@}"
    INV_ROWS[$id]=""; INV_COUNT[$id]=0
}

inventory_add_row() {
    local id="$1" f=""; shift
    [[ -n "${INV_TITLE[$id]+x}" ]] || return 1
    local -a clean=()
    for f in "$@"; do
        f="${f//$INV_FS/ }"; f="${f//$INV_RS/ }"
        clean+=("$f")
    done
    if [[ -n "${INV_ROWS[$id]}" ]]; then
        INV_ROWS[$id]+="$INV_RS${(pj:\x1f:)clean}"
    else
        INV_ROWS[$id]="${(pj:\x1f:)clean}"
    fi
    INV_COUNT[$id]=$(( ${INV_COUNT[$id]} + 1 ))
}

# JSON string body of $1 in REPLY, without a subshell (inventories hold thousands of cells).
# "<" is escaped too, so the JSON can sit inside a <script> element without closing it.
_inv_json_str() {
    local s="$1"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"; s="${s//$'\t'/\\t}"; s="${s//$'\r'/\\r}"
    s="${s//</\\u003c}"; s="${s//>/\\u003e}"; s="${s//&/\\u0026}"
    if [[ "$s" == *[[:cntrl:]]* ]]; then
        local out="" ch="" i
        for (( i = 1; i <= ${#s}; i++ )); do
            ch="${s[i]}"
            if [[ "$ch" == [[:cntrl:]] ]]; then out+=$(printf '\\u%04x' "'$ch"); else out+="$ch"; fi
        done
        s="$out"
    fi
    REPLY="$s"
}

# {"tables":[{"id":..,"title":..,"note":..,"columns":[{"label":..,"type":..,"ref":..}],"rows":[[..]]}]}
inventory_json() {
    local id="" col="" label="" type="" ref="" row="" f="" out='{"tables":[' first_t=1 first_r=1 first_f=1
    local -a cols rows fields
    for id in "${INV_ORDER[@]}"; do
        (( first_t )) || out+=','; first_t=0
        _inv_json_str "$id"; out+="{\"id\":\"$REPLY\""
        _inv_json_str "${INV_TITLE[$id]}"; out+=",\"title\":\"$REPLY\""
        _inv_json_str "${INV_NOTE[$id]}"; out+=",\"note\":\"$REPLY\",\"columns\":["
        cols=("${(@ps:\x1f:)INV_COLS[$id]}")
        first_f=1
        for col in "${cols[@]}"; do
            label="${col%%:*}"; type="text"; ref=""
            [[ "$col" == *:* ]] && type="${col#*:}"
            if [[ "$type" == ref=* ]]; then ref="${type#ref=}"; type="ref"; fi
            (( first_f )) || out+=','; first_f=0
            _inv_json_str "$label"; out+="{\"label\":\"$REPLY\""
            _inv_json_str "$type"; out+=",\"type\":\"$REPLY\""
            _inv_json_str "$ref"; out+=",\"ref\":\"$REPLY\"}"
        done
        out+='],"rows":['
        first_r=1
        if [[ -n "${INV_ROWS[$id]}" ]]; then
            rows=("${(@ps:\x1e:)INV_ROWS[$id]}")
            for row in "${rows[@]}"; do
                (( first_r )) || out+=','; first_r=0
                fields=("${(@ps:\x1f:)row}")
                out+='['; first_f=1
                for f in "${fields[@]}"; do
                    (( first_f )) || out+=','; first_f=0
                    _inv_json_str "$f"; out+="\"$REPLY\""
                done
                out+=']'
            done
        fi
        out+=']}'
    done
    out+=']}'
    print -r -- "$out"
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
                --cis-macos 'N/A' --mscp 'os_secure_enclave' \
                --recommendation 'No action required. Every Apple Silicon Mac ships with a Secure Enclave.'
        else
            add_audit_result --category 'Hardware, Firmware & Platform Integrity' \
                --control 'Secure Enclave Presence' --status WARN --severity Medium \
                --current 'Secure Enclave not detected via ioreg' --recommended 'Secure Enclave present' \
                --cis 'CIS 10.5' --nist 'IA-3, SC-28' --cis-macos 'N/A' --mscp 'os_secure_enclave' \
                --recommendation 'Unexpected on Apple Silicon hardware. Verify with "system_profiler SPiBridgeDataType" and Apple Diagnostics; this may indicate a query failure rather than a real absence.'
        fi
    else
        run_root system_profiler SPiBridgeDataType
        if [[ "$ROOT_CMD_OUTPUT" == *"Apple T2"* ]]; then
            add_audit_result --category 'Hardware, Firmware & Platform Integrity' \
                --control 'Secure Enclave Presence' --status PASS --severity High \
                --current 'Apple T2 Security Chip detected' --recommended 'T2 Security Chip present' \
                --cis 'CIS 10.5' --nist 'IA-3, SC-28' --cis-macos 'N/A' --mscp 'os_secure_enclave' \
                --recommendation 'No action required.'
        else
            add_audit_result --category 'Hardware, Firmware & Platform Integrity' \
                --control 'Secure Enclave Presence' --status WARN --severity High \
                --current 'No T2 Security Chip detected' --recommended 'T2 Security Chip present' \
                --cis 'CIS 10.5' --nist 'IA-3, SC-28' --cis-macos 'N/A' --mscp 'os_secure_enclave' \
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
        --cis-macos 'N/A' --mscp 'N/A' \
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
        --cis-macos 'N/A' --mscp 'N/A' \
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
            --nsa 'NSA/CISA macOS Hardening Guidance' --cis-macos 'CIS-macOS 5.1.2' --mscp 'os_sip_enable' \
            --recommendation 'Re-enable SIP: boot into Recovery (Apple Silicon: hold the power button; Intel: Cmd+R) and run "csrutil enable" from Terminal, then reboot.'
    elif [[ "$ROOT_CMD_OUTPUT" == *"enabled"* ]]; then
        add_audit_result --category 'SIP & Kernel Security' --control 'System Integrity Protection (SIP)' \
            --status PASS --severity Critical --current "$ROOT_CMD_OUTPUT" \
            --recommended 'System Integrity Protection status: enabled.' \
            --cis 'CIS 10.5' --nist 'SI-7, SC-28' --mitre 'T1553.006' --iso27001 'A.8.24' --nis2 'Art.21(2)(d)' \
            --nsa 'NSA/CISA macOS Hardening Guidance' --cis-macos 'CIS-macOS 5.1.2' --mscp 'os_sip_enable' \
            --recommendation 'No action required.'
    else
        add_audit_result --category 'SIP & Kernel Security' --control 'System Integrity Protection (SIP)' \
            --status WARN --severity Low --current "Query failed or unrecognized output: $ROOT_CMD_OUTPUT" \
            --recommended 'System Integrity Protection status: enabled.' \
            --cis 'CIS 10.5' --nist 'SI-7, SC-28' --cis-macos 'CIS-macOS 5.1.2' --mscp 'os_sip_enable' \
            --recommendation 'Unable to determine SIP status via csrutil; verify manually with "csrutil status" in Terminal.'
    fi
}

check_sip_custom_configuration() {
    run_root csrutil status

    if [[ "$ROOT_CMD_STATUS" -ne 0 ]]; then
        add_audit_result --category 'SIP & Kernel Security' --control 'SIP Custom Configuration (Partial Disable)' \
            --status WARN --severity Low --current "csrutil query failed: $ROOT_CMD_OUTPUT" \
            --recommended 'No custom SIP exceptions; full default protection set' \
            --cis-macos 'CIS-macOS 5.1.2' --mscp 'os_sip_enable' \
            --recommendation 'Unable to query SIP configuration; verify manually with "csrutil status" in Terminal.'
    elif [[ "$ROOT_CMD_OUTPUT" == *"Custom Configuration"* ]]; then
        local disabled_items
        disabled_items=$(print -r -- "$ROOT_CMD_OUTPUT" | grep ': disabled' | sed 's/^[[:space:]]*//' | paste -sd ';' - | sed 's/;/; /g')
        [[ -z "$disabled_items" ]] && disabled_items="Custom configuration detected but no specific disabled component parsed"
        add_audit_result --category 'SIP & Kernel Security' --control 'SIP Custom Configuration (Partial Disable)' \
            --status WARN --severity High --current "$disabled_items" \
            --recommended 'No custom SIP exceptions; full default protection set' \
            --cis 'CIS 10.5' --nist 'SI-7, SC-28' --mitre 'T1553.006' --iso27001 'A.8.24' --nis2 'Art.21(2)(d)' \
            --cis-macos 'CIS-macOS 5.1.2' --mscp 'os_sip_enable' \
            --recommendation 'A custom SIP configuration was detected, weakening specific protections. Boot into Recovery and run "csrutil clear" then "csrutil enable" to restore the full default protection set unless this is a deliberate, documented exception.'
    else
        add_audit_result --category 'SIP & Kernel Security' --control 'SIP Custom Configuration (Partial Disable)' \
            --status PASS --severity High --current 'No custom SIP configuration detected' \
            --recommended 'No custom SIP exceptions; full default protection set' \
            --cis 'CIS 10.5' --nist 'SI-7, SC-28' --cis-macos 'CIS-macOS 5.1.2' --mscp 'os_sip_enable' \
            --recommendation 'No action required.'
    fi
}

check_third_party_system_extensions() {
    run_root systemextensionsctl list

    if [[ "$ROOT_CMD_STATUS" -ne 0 ]]; then
        add_audit_result --category 'SIP & Kernel Security' --control 'Third-Party System Extensions Inventory' \
            --status WARN --severity Low --current "systemextensionsctl query failed: $ROOT_CMD_OUTPUT" \
            --recommended 'Every active system extension is recognized and required' \
            --cis-macos 'N/A' --mscp 'N/A' \
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
            --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'Review "systemextensionsctl list" output and confirm each non-Apple system extension is recognized, still needed, and from a trusted vendor.'
    else
        add_audit_result --category 'SIP & Kernel Security' --control 'Third-Party System Extensions Inventory' \
            --status PASS --severity Medium \
            --current "$activated_lines total active system extension(s), none non-Apple" \
            --recommended 'Every active system extension is recognized and required' \
            --cis 'CIS 2.5' --nist 'CM-7, SI-7' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'No action required.'
    fi
}

check_nvram_csr_override() {
    run_root nvram csr-active-config

    if [[ "$ROOT_CMD_STATUS" -eq 0 && -n "$ROOT_CMD_OUTPUT" ]]; then
        add_audit_result --category 'SIP & Kernel Security' --control 'NVRAM SIP Configuration Override Present' \
            --status WARN --severity Medium --current "$ROOT_CMD_OUTPUT" \
            --recommended 'No csr-active-config NVRAM variable set (default SIP configuration)' \
            --cis 'CIS 10.5' --nist 'SI-7, SC-28' --cis-macos 'CIS-macOS 5.1.2' --mscp 'os_sip_enable' \
            --recommendation 'An explicit SIP configuration override is stored in NVRAM. Confirm this was set deliberately; clear it with "nvram -d csr-active-config" from Recovery if not.'
    elif [[ "$ROOT_CMD_OUTPUT" == *"Error getting variable"* ]]; then
        add_audit_result --category 'SIP & Kernel Security' --control 'NVRAM SIP Configuration Override Present' \
            --status PASS --severity Medium --current 'No csr-active-config NVRAM variable set' \
            --recommended 'No csr-active-config NVRAM variable set (default SIP configuration)' \
            --cis 'CIS 10.5' --nist 'SI-7, SC-28' --cis-macos 'CIS-macOS 5.1.2' --mscp 'os_sip_enable' \
            --recommendation 'No action required.'
    else
        add_audit_result --category 'SIP & Kernel Security' --control 'NVRAM SIP Configuration Override Present' \
            --status WARN --severity Low --current "nvram query failed: $ROOT_CMD_OUTPUT" \
            --recommended 'No csr-active-config NVRAM variable set (default SIP configuration)' \
            --cis-macos 'CIS-macOS 5.1.2' --mscp 'os_sip_enable' \
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
            --cis-macos 'CIS-macOS 2.6.6' --mscp 'system_settings_filevault_enforce' \
            --recommendation 'No action required.'
    elif [[ "$ROOT_CMD_OUTPUT" == *"FileVault is Off."* ]]; then
        add_audit_result --category 'Volume Encryption & Data-at-Rest (FileVault)' --control 'FileVault Status' \
            --status FAIL --severity Critical --current "$ROOT_CMD_OUTPUT" --recommended 'FileVault is On.' \
            --cis 'CIS 3.11' --nist 'SC-28' --mitre 'T1486 (Data Encrypted for Impact — inverse control)' \
            --iso27001 'A.8.24' --nis2 'Art.21(2)(h)' --nsa 'NSA/CISA Data-at-Rest Encryption Guidance' \
            --cis-macos 'CIS-macOS 2.6.6' --mscp 'system_settings_filevault_enforce' \
            --recommendation 'Enable FileVault via System Settings > Privacy & Security > FileVault, or run "sudo fdesetup enable" from Terminal.'
    else
        add_audit_result --category 'Volume Encryption & Data-at-Rest (FileVault)' --control 'FileVault Status' \
            --status WARN --severity Low --current "Query failed or unrecognized output: $ROOT_CMD_OUTPUT" \
            --recommended 'FileVault is On.' \
            --cis 'CIS 3.11' --nist 'SC-28' --cis-macos 'CIS-macOS 2.6.6' --mscp 'system_settings_filevault_enforce' \
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
            --cis-macos 'CIS-macOS 2.6.6' --mscp 'system_settings_filevault_enforce, os_filevault_autologin_disable' \
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
            --cis-macos 'CIS-macOS 2.6.6' --mscp 'system_settings_filevault_enforce, os_filevault_autologin_disable' \
            --recommendation 'No action required.'
    else
        add_audit_result --category 'Volume Encryption & Data-at-Rest (FileVault)' \
            --control 'FileVault Deferred Enablement Pending' \
            --status WARN --severity Low --current "fdesetup query failed: $ROOT_CMD_OUTPUT" \
            --recommended 'No deferred enablement pending' \
            --cis-macos 'CIS-macOS 2.6.6' --mscp 'system_settings_filevault_enforce, os_filevault_autologin_disable' \
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
            --recommended 'N/A' --cis-macos 'CIS-macOS 2.6.6' --mscp 'N/A' \
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
        --cis-macos 'CIS-macOS 2.6.6' --mscp 'N/A' \
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
            --recommended 'N/A' --cis-macos 'CIS-macOS 2.6.6' --mscp 'N/A' \
            --recommendation 'Confirm this recovery key completes escrow to your MDM/institutional record; do not rely on it remaining only on this device.'
    else
        add_audit_result --category 'Volume Encryption & Data-at-Rest (FileVault)' \
            --control 'FileVault Recovery Key Escrow' \
            --status INFO --severity Informational \
            --current 'No pending local personal recovery key file found; escrow status cannot be reliably determined from the command line' \
            --recommended 'N/A' --cis-macos 'CIS-macOS 2.6.6' --mscp 'N/A' \
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
            --cis-macos 'CIS-macOS 2.6.5' --mscp 'os_gatekeeper_enable' \
            --recommendation 'No action required.'
    elif [[ "$ROOT_CMD_OUTPUT" == *"assessments disabled"* ]]; then
        add_audit_result --category 'Gatekeeper, Notarization & Application Control' \
            --control 'Gatekeeper Status' \
            --status FAIL --severity High --current "$ROOT_CMD_OUTPUT" \
            --recommended 'assessments enabled' \
            --cis 'CIS 2.5' --nist 'CM-7, SI-7' --mitre 'T1553.001 (Gatekeeper Bypass)' --iso27001 'A.8.19' \
            --nis2 'Art.21(2)(d)' --nsa 'NSA/CISA macOS Hardening Guidance' \
            --cis-macos 'CIS-macOS 2.6.5' --mscp 'os_gatekeeper_enable' \
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
            --cis 'CIS 2.5' --nist 'CM-7, SI-7' --cis-macos 'CIS-macOS 2.6.5' --mscp 'os_gatekeeper_enable' \
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
            --cis-macos 'CIS-macOS 2.6.5' --mscp 'N/A' \
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
        --cis-macos 'CIS-macOS 2.6.5' --mscp 'N/A' \
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
        --cis-macos 'CIS-macOS 2.6.5' --mscp 'N/A' \
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
        'XProtect Update Freshness') mscp_id='N/A' ;;
        'MRT Update Freshness') mscp_id='N/A' ;;
        *) mscp_id='N/A' ;;
    esac

    if [[ ! -f "$plist_path" ]]; then
        # Fault isolation: a missing bundle gets its own distinct --current
        # text, never silently folded into the "stale" WARN below.
        add_audit_result --category 'Malware Defense (XProtect / MRT / EDR)' --control "$control_name" \
            --status WARN --severity Medium --current "${bundle_label} bundle not found at expected path" \
            --recommended 'Definitions updated within the last 30 days' \
            --cis 'CIS 7.2' --nist 'SI-3' --mitre 'T1204 (User Execution)' --iso27001 'A.8.7' \
            --nis2 'Art.21(2)(d)' --nsa 'NSA/CISA Malware Defense Guidance' --cis-macos "$( [[ "$control_name" == XProtect* ]] && print 'CIS-macOS 5.10' || print 'N/A')" \
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
            --nis2 'Art.21(2)(d)' --nsa 'NSA/CISA Malware Defense Guidance' --cis-macos "$( [[ "$control_name" == XProtect* ]] && print 'CIS-macOS 5.10' || print 'N/A')" \
            --mscp "$mscp_id" \
            --recommendation 'No action required.'
    else
        add_audit_result --category 'Malware Defense (XProtect / MRT / EDR)' --control "$control_name" \
            --status WARN --severity Medium --current "Version=$version, last updated $age_days day(s) ago" \
            --recommended 'Definitions updated within the last 30 days' \
            --cis 'CIS 7.2' --nist 'SI-3' --mitre 'T1204 (User Execution)' --iso27001 'A.8.7' \
            --nis2 'Art.21(2)(d)' --nsa 'NSA/CISA Malware Defense Guidance' --cis-macos "$( [[ "$control_name" == XProtect* ]] && print 'CIS-macOS 5.10' || print 'N/A')" \
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
    # Apple stopped updating MRT once XProtect Remediator replaced it, so
    # an old MRT date is expected, not a finding (a real run reported
    # "1579 day(s) ago" as WARN Medium).
    if [[ -d "${XPROTECT_APP:-/Library/Apple/System/Library/CoreServices/XProtect.app}" ]]; then
        add_audit_result --category 'Malware Defense (XProtect / MRT / EDR)' --control 'MRT Update Freshness' \
            --status INFO --severity Informational \
            --current 'MRT is retired on this macOS; XProtect Remediator performs its scans (see XProtect Remediator Scan Results)' \
            --recommended 'N/A' --cis-macos 'N/A' --mscp 'N/A' --recommendation 'Informational only.'
        return
    fi
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
            --recommended 'N/A' --cis-macos 'N/A' --mscp 'N/A' \
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
            --nis2 'Art.21(2)(d)' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'Informational only. A recognized third-party EDR/MDE agent process is running.'
    else
        add_audit_result --category 'Malware Defense (XProtect / MRT / EDR)' --control 'Third-Party EDR/MDE Presence' \
            --status WARN --severity Medium --current 'No known third-party EDR/MDE agent process detected' \
            --recommended 'A recognized EDR/MDE agent process is running' \
            --cis 'CIS 7.1' --nist 'SI-3' --mitre 'T1562.001 (Disable or Modify Tools)' --iso27001 'A.8.7' \
            --nis2 'Art.21(2)(d)' --cis-macos 'N/A' --mscp 'N/A' \
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
        --recommended 'N/A' --cis-macos 'N/A' --mscp 'N/A' \
        --recommendation 'Informational only. This reflects Endpoint Security framework registration specifically, which is a stronger EDR-presence signal than a running-process check.'
}

# XProtect Remediator scans (run by macOS when idle) log one structured
# result per remediator to the unified log: subsystem
# com.apple.XProtectFramework.PluginAPI, category XPEvent.structured,
# eventMessage {"status_code":20,"status_message":"NoThreatDetected",...}
# (verified live). Anything other than NoThreatDetected / codes 0 and 20
# means a remediator found or acted on something — an actual detection,
# not a configuration state. 7-day window, prefetched in main().
XPR_LOG_PREDICATE='subsystem == "com.apple.XProtectFramework.PluginAPI" && category == "XPEvent.structured"'

xpr_log_query() {
    "${LOG_BIN:-/usr/bin/log}" show --last 7d --style ndjson --predicate "$XPR_LOG_PREDICATE"
}

check_xprotect_remediator_results() {
    run_prefetched xpr_log xpr_log_query
    local -a fw
    fw=(--recommended 'Every XProtect Remediator scan in the last 7 days reports NoThreatDetected'
        --cis 'CIS 10.1' --nist 'SI-3, SI-4' --mitre 'T1204 (User Execution)' --iso27001 'A.8.7'
        --nis2 'Art.21(2)(e)' --cis-macos 'CIS-macOS 5.10' --mscp 'N/A')

    if [[ $ROOT_CMD_STATUS -ne 0 ]]; then
        add_audit_result --category 'Malware Defense (XProtect / MRT / EDR)' --control 'XProtect Remediator Scan Results' \
            --status WARN --severity Low --current "Unified log query failed: ${ROOT_CMD_OUTPUT[1,200]}" "${fw[@]}" \
            --recommendation 'Re-run with sudo; reading XProtect Remediator results requires access to the unified log.'
        return 0
    fi

    local line="" remediator="" message="" code="" caused=""
    local -a detections
    local -A seen_remediators
    local scans=0
    for line in "${(@f)ROOT_CMD_OUTPUT}"; do
        [[ "$line" == *XPEvent.structured* ]] || continue
        [[ "$line" =~ 'XProtectRemediator([A-Za-z0-9]+)"' ]] && remediator="${match[1]}" || remediator="unknown"
        [[ "$line" =~ 'status_message\\":\\"([^\\]*)\\"' ]] && message="${match[1]}" || message=""
        [[ "$line" =~ 'status_code\\":(-?[0-9]+)' ]] && code="${match[1]}" || code=""
        scans=$((scans + 1)); seen_remediators[$remediator]=1
        if [[ "$message" != NoThreatDetected && "$code" != 20 && "$code" != 0 ]]; then
            caused=""
            # caused_by paths are JSON-escaped twice in ndjson (\/ or \\/):
            # drop every backslash and quote; macOS paths carry neither.
            [[ "$line" =~ 'caused_by\\":\[([^]]*)\]' ]] && { caused="${match[1]//\\/}"; caused="${caused//\"/}"; }
            [[ "$line" =~ '"timestamp":"([0-9-]+ [0-9:]+)' ]] || match=("")
            detections+=("${match[1]:-?} $remediator: ${message:-status $code}${caused:+ (caused by: ${caused[1,200]})}")
        fi
    done

    if [[ ${#detections[@]} -gt 0 ]]; then
        add_audit_result --category 'Malware Defense (XProtect / MRT / EDR)' --control 'XProtect Remediator Scan Results' \
            --status FAIL --severity Critical --current "${#detections[@]} XProtect Remediator result(s) other than NoThreatDetected" \
            --details "${(F)detections}" "${fw[@]}" \
            --recommendation 'Treat as a possible active infection: preserve the unified log ("log collect --last 7d") and the listed paths for forensics, then investigate the remediator family named. XProtect may already have removed the payload, but the initial access vector (download, paste-in-Terminal lure, cracked app) remains.'
    elif [[ $scans -eq 0 ]]; then
        add_audit_result --category 'Malware Defense (XProtect / MRT / EDR)' --control 'XProtect Remediator Scan Results' \
            --status WARN --severity Low --current 'No XProtect Remediator scan results logged in the last 7 days' "${fw[@]}" \
            --recommendation 'macOS runs XProtect Remediator scans in the background when the Mac is idle (and on power). If none ran in a week, confirm XProtect is current and the Mac is not always asleep or busy.'
    else
        add_audit_result --category 'Malware Defense (XProtect / MRT / EDR)' --control 'XProtect Remediator Scan Results' \
            --status PASS --severity Critical --current "$scans scan result(s) from ${#seen_remediators} remediator(s) in 7 days, no threats detected" \
            --details "${(F)${(@ko)seen_remediators}}" "${fw[@]}" --recommendation 'No action required.'
    fi
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
                --nis2 'Art.21(2)(i)' --cis-macos "$( [[ "$control" == 'Full Disk Access Grants' ]] && print 'CIS-macOS 2.6.2.1' || print 'N/A')" --mscp 'N/A' \
                --recommendation 'Grant Full Disk Access to the terminal application (or shell) used to run this script in System Settings > Privacy & Security > Full Disk Access, then re-run.'
            ;;
        QUERY_ERROR:*)
            add_audit_result --category 'TCC & Privacy Controls' --control "$control" \
                --status WARN --severity Low \
                --current "TCC database query failed: ${result#QUERY_ERROR:}" \
                --recommended 'N/A' \
                --cis 'CIS 3.3' --nist 'AC-6' --mitre 'T1005 (Data from Local System)' --iso27001 'A.8.3' \
                --nis2 'Art.21(2)(i)' --cis-macos "$( [[ "$control" == 'Full Disk Access Grants' ]] && print 'CIS-macOS 2.6.2.1' || print 'N/A')" --mscp 'N/A' \
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
                --nis2 'Art.21(2)(i)' --cis-macos "$( [[ "$control" == 'Full Disk Access Grants' ]] && print 'CIS-macOS 2.6.2.1' || print 'N/A')" --mscp 'N/A' \
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
        --nis2 'Art.21(2)(i)' --cis-macos 'N/A' --mscp 'N/A' \
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
            --nis2 'Art.21(2)(i)' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'Grant Full Disk Access to the terminal application (or shell) used to run this script in System Settings > Privacy & Security > Full Disk Access, then re-run.'
    else
        add_audit_result --category 'TCC & Privacy Controls' --control 'Camera & Microphone Grants' \
            --status WARN --severity Low \
            --current "TCC database query failed: ${result#QUERY_ERROR:}" \
            --recommended 'N/A' \
            --cis 'CIS 3.3' --nist 'AC-6' --mitre 'T1005 (Data from Local System)' --iso27001 'A.8.3' \
            --nis2 'Art.21(2)(i)' --cis-macos 'N/A' --mscp 'N/A' \
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
            --cis 'CIS 3.3' --nist 'AC-6, SI-7' --cis-macos 'N/A' --mscp 'N/A' \
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
            --nis2 'Art.21(2)(d)' --nsa 'NSA/CISA macOS Hardening Guidance' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'This indicates SIP is compromised or the TCC database was tampered with outside Apple'"'"'s normal management path; treat as a possible active-compromise indicator and investigate before remediating.'
    else
        add_audit_result --category 'TCC & Privacy Controls' --control 'TCC Database File Permissions' \
            --status PASS --severity Critical \
            --current "$owner_group $mode" \
            --recommended 'root:wheel (or root:_tcc), no group/other write bit' \
            --cis 'CIS 3.3' --nist 'AC-6, SI-7' --mitre 'T1548.006 (TCC Manipulation)' --iso27001 'A.8.3' \
            --nis2 'Art.21(2)(d)' --nsa 'NSA/CISA macOS Hardening Guidance' --cis-macos 'N/A' --mscp 'N/A' \
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
            --cis 'CIS 5.4' --nist 'AC-6, IA-2' --cis-macos 'CIS-macOS 5.6' --mscp 'os_root_disable' \
            --recommendation 'Unable to determine root account status; verify manually with "dscl . -read /Users/root Password".'
    # Exact match, whitespace removed: a disabled root reads "Password: *",
    # an enabled one "Password: ********" — which a substring match on
    # "Password: *" also accepted (caught by test-checks-defense-identity).
    elif [[ "${ROOT_CMD_OUTPUT//[[:space:]]/}" == 'Password:*' ]]; then
        add_audit_result --category 'Identity, Accounts & Privilege Management' \
            --control 'Root Account Disabled' \
            --status PASS --severity Critical --current "$ROOT_CMD_OUTPUT" \
            --recommended 'Password: *' \
            --cis 'CIS 5.4' --nist 'AC-6, IA-2' --mitre 'T1078.001 (Default Accounts)' --iso27001 'A.8.2' \
            --nis2 'Art.21(2)(i)' --nsa 'NSA/CISA macOS Hardening Guidance' --cis-macos 'CIS-macOS 5.6' --mscp 'os_root_disable' \
            --recommendation 'No action required.'
    else
        add_audit_result --category 'Identity, Accounts & Privilege Management' \
            --control 'Root Account Disabled' \
            --status FAIL --severity Critical --current "$ROOT_CMD_OUTPUT" \
            --recommended 'Password: *' \
            --cis 'CIS 5.4' --nist 'AC-6, IA-2' --mitre 'T1078.001 (Default Accounts)' --iso27001 'A.8.2' \
            --nis2 'Art.21(2)(i)' --nsa 'NSA/CISA macOS Hardening Guidance' --cis-macos 'CIS-macOS 5.6' --mscp 'os_root_disable' \
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
            --nis2 'Art.21(2)(i)' --cis-macos 'CIS-macOS 2.13.1' --mscp 'system_settings_guest_account_disable' \
            --recommendation 'Disable the Guest account: System Settings > Users & Groups > Guest User, or "sudo defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false".'
    else
        add_audit_result --category 'Identity, Accounts & Privilege Management' \
            --control 'Guest Account Disabled' \
            --status PASS --severity High --current "GuestEnabled=$guest_enabled" \
            --recommended 'GuestEnabled=0' \
            --cis 'CIS 5.4' --nist 'AC-6, IA-2' --mitre 'T1078.001 (Default Accounts)' --iso27001 'A.8.2' \
            --nis2 'Art.21(2)(i)' --cis-macos 'CIS-macOS 2.13.1' --mscp 'system_settings_guest_account_disable' \
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
            --recommended 'N/A' --cis-macos 'N/A' --mscp 'N/A' \
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
        --cis 'CIS 5.1' --nist 'AC-6' --iso27001 'A.8.2' --cis-macos 'N/A' --mscp 'N/A' \
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
            --nis2 'Art.21(2)(i)' --cis-macos 'CIS-macOS 5.2' --mscp 'os_policy_banner_loginwindow_enforce' \
            --recommendation 'Informational only. Review the policy content matches organizational requirements.'
    else
        add_audit_result --category 'Identity, Accounts & Privilege Management' \
            --control 'Password Policy Configured' \
            --status WARN --severity Medium \
            --current 'No explicit password content policy configured' \
            --recommended 'A password content policy is configured' \
            --cis 'CIS 5.2' --nist 'IA-5' --mitre 'T1110 (Brute Force)' --iso27001 'A.8.5' \
            --nis2 'Art.21(2)(i)' --cis-macos 'CIS-macOS 5.2' --mscp 'os_policy_banner_loginwindow_enforce' \
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
        # All leading whitespace, not one character: an indented
        # "#   ... NOPASSWD" comment must still count as a comment.
        trimmed="${line#"${line%%[![:space:]]*}"}"
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
    # "Firewall is enabled. (State = 1)", "... disabled. (State = 0)" and
    # "Firewall is blocking all non-essential incoming connections.
    # (State = 2)" (verified live): the State number is authoritative.
    local fw_state=""
    [[ "$ROOT_CMD_OUTPUT" =~ 'State = ([0-9])' ]] && fw_state="${match[1]}"

    if [[ "$fw_state" == 1 || "$fw_state" == 2 || ( -z "$fw_state" && "$ROOT_CMD_OUTPUT" == *"is enabled"* ) ]]; then
        add_audit_result --category 'Network Firewall & Packet Filtering' --control 'Firewall State' \
            --status PASS --severity High --current "$ROOT_CMD_OUTPUT" \
            --recommended 'Firewall enabled' \
            --cis 'CIS 4.1' --nist 'SC-7' --mitre 'T1562.004 (Disable or Modify System Firewall)' --iso27001 'A.8.20' \
            --nis2 'Art.21(2)(d)' --nsa 'NSA/CISA macOS Hardening Guidance' --cis-macos 'CIS-macOS 2.2.1' --mscp 'system_settings_firewall_enable' \
            --recommendation 'No action required.'
    elif [[ "$fw_state" == 0 || ( -z "$fw_state" && "$ROOT_CMD_OUTPUT" == *"is disabled"* ) ]]; then
        add_audit_result --category 'Network Firewall & Packet Filtering' --control 'Firewall State' \
            --status FAIL --severity High --current "$ROOT_CMD_OUTPUT" \
            --recommended 'Firewall enabled' \
            --cis 'CIS 4.1' --nist 'SC-7' --mitre 'T1562.004 (Disable or Modify System Firewall)' --iso27001 'A.8.20' \
            --nis2 'Art.21(2)(d)' --nsa 'NSA/CISA macOS Hardening Guidance' --cis-macos 'CIS-macOS 2.2.1' --mscp 'system_settings_firewall_enable' \
            --recommendation 'Enable the firewall: System Settings > Network > Firewall, or "sudo \"$SOCKETFILTERFW\" --setglobalstate on".'
    else
        # Fault isolation: a failing/unrecognized query must never be
        # reported identically to a verified-enabled or verified-disabled
        # firewall state above.
        add_audit_result --category 'Network Firewall & Packet Filtering' --control 'Firewall State' \
            --status WARN --severity Low --current "Query failed or unrecognized output: $ROOT_CMD_OUTPUT" \
            --recommended 'Firewall enabled' \
            --cis 'CIS 4.1' --nist 'SC-7' --cis-macos 'CIS-macOS 2.2.1' --mscp 'system_settings_firewall_enable' \
            --recommendation 'Unable to determine firewall state; verify manually with "socketfilterfw --getglobalstate".'
    fi
}

check_firewall_stealth_mode() {
    run_root "$SOCKETFILTERFW" --getstealthmode
    # Tahoe prints "Firewall stealth mode is on|off" (verified live);
    # older releases printed "Stealth mode enabled|disabled".

    if [[ "$ROOT_CMD_OUTPUT" == *"mode is on"* || "$ROOT_CMD_OUTPUT" == *"mode enabled"* ]]; then
        add_audit_result --category 'Network Firewall & Packet Filtering' --control 'Firewall Stealth Mode' \
            --status PASS --severity Medium --current "$ROOT_CMD_OUTPUT" \
            --recommended 'Stealth mode enabled' \
            --cis 'CIS 4.1' --nist 'SC-7' --mitre 'T1046 (Network Service Discovery)' --iso27001 'A.8.20' \
            --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 2.2.2' --mscp 'system_settings_firewall_stealth_mode_enable' \
            --recommendation 'No action required.'
    elif [[ "$ROOT_CMD_OUTPUT" == *"mode is off"* || "$ROOT_CMD_OUTPUT" == *"mode disabled"* ]]; then
        add_audit_result --category 'Network Firewall & Packet Filtering' --control 'Firewall Stealth Mode' \
            --status WARN --severity Medium --current "$ROOT_CMD_OUTPUT" \
            --recommended 'Stealth mode enabled' \
            --cis 'CIS 4.1' --nist 'SC-7' --mitre 'T1046 (Network Service Discovery)' --iso27001 'A.8.20' \
            --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 2.2.2' --mscp 'system_settings_firewall_stealth_mode_enable' \
            --recommendation 'Enable stealth mode: "sudo \"$SOCKETFILTERFW\" --setstealthmode on".'
    else
        # Fault isolation: a failing/unrecognized query is a distinct,
        # lower-confidence WARN from the explicit "disabled" branch above.
        add_audit_result --category 'Network Firewall & Packet Filtering' --control 'Firewall Stealth Mode' \
            --status WARN --severity Low --current "Query failed or unrecognized output: $ROOT_CMD_OUTPUT" \
            --recommended 'Stealth mode enabled' \
            --cis 'CIS 4.1' --nist 'SC-7' --cis-macos 'CIS-macOS 2.2.2' --mscp 'system_settings_firewall_stealth_mode_enable' \
            --recommendation 'Unable to determine stealth mode state; verify manually with "socketfilterfw --getstealthmode".'
    fi
}

check_firewall_block_all_incoming() {
    run_root "$SOCKETFILTERFW" --getblockall

    # Always INFO: blocking all incoming is stricter but breaks legitimate
    # sharing use cases — environment-dependent, not a judgement.
    add_audit_result --category 'Network Firewall & Packet Filtering' --control 'Block All Incoming Connections' \
        --status INFO --severity Informational --current "$ROOT_CMD_OUTPUT" \
        --recommended 'N/A' --cis-macos 'N/A' --mscp 'N/A' \
        --recommendation 'Informational only. Whether to block all incoming connections depends on whether this Mac needs to offer any sharing services.'
}

check_firewall_signed_app_auto_allow() {
    run_root "$SOCKETFILTERFW" --getallowsigned

    # Always INFO: Apple's default of auto-allowing signed built-in
    # software is expected behavior, not a misconfiguration.
    add_audit_result --category 'Network Firewall & Packet Filtering' --control 'Signed Application Auto-Allow' \
        --status INFO --severity Informational --current "$ROOT_CMD_OUTPUT" \
        --recommended 'N/A' --cis-macos 'N/A' --mscp 'N/A' \
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
            --recommended 'N/A' --cis-macos 'N/A' --mscp 'N/A' \
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
        --recommended 'N/A' --cis-macos 'N/A' --mscp 'N/A' \
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
        # All leading whitespace, not one character: an indented
        # "#   ... NOPASSWD" comment must still count as a comment.
        trimmed="${line#"${line%%[![:space:]]*}"}"
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
            mitre='T1021.005 (VNC)'; cis_macos='CIS-macOS 2.3.3.1'
            mscp_id='system_settings_screen_sharing_disable'; nsa='NSA/CISA macOS Hardening Guidance' ;;
        'Remote Management (ARD)')
            mitre='T1021.005 (VNC)'; cis_macos='CIS-macOS 2.3.3.5'
            mscp_id='system_settings_remote_management_disable'; nsa='NSA/CISA macOS Hardening Guidance' ;;
        'File Sharing (SMB)')
            mitre='T1021.002 (SMB/Windows Admin Shares)'; cis_macos='CIS-macOS 2.3.3.2'
            mscp_id='system_settings_smbd_disable'; nsa='N/A' ;;
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
            --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 2.3.3.4' --mscp 'system_settings_ssh_disable' \
            --recommendation 'Disable via System Settings > General > Sharing > Remote Login unless SSH access is required (see the SSH Server & Client Hardening domain for hardening if it is), or "sudo systemsetup -setremotelogin off".'
    elif [[ "$ROOT_CMD_OUTPUT" == *"Off"* ]]; then
        add_audit_result --category 'Remote Access & Sharing Services' --control 'Remote Login (SSH) Toggle' \
            --status PASS --severity Medium --current 'Remote Login: Off' \
            --recommended 'Remote Login: Off' \
            --cis 'CIS 4.9' --nist 'AC-17' --mitre 'T1021.004 (SSH)' --iso27001 'A.8.20' \
            --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 2.3.3.4' --mscp 'system_settings_ssh_disable' \
            --recommendation 'No action required.'
    else
        # Fault isolation: a failing/unrecognized query must never be
        # reported identically to a verified "Off" result above.
        add_audit_result --category 'Remote Access & Sharing Services' --control 'Remote Login (SSH) Toggle' \
            --status WARN --severity Low --current "Query failed or unrecognized output: $ROOT_CMD_OUTPUT" \
            --recommended 'Remote Login: Off' \
            --cis 'CIS 4.9' --nist 'AC-17' --cis-macos 'CIS-macOS 2.3.3.4' --mscp 'system_settings_ssh_disable' \
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

# `sshd -T` exits "no hostkeys available" until Remote Login has been
# turned on once (verified live on Tahoe), so every check read "not
# available". `sshd -G` prints the same effective configuration without
# host keys (mSCP's method). The settings only matter while Remote Login
# is on, so with it off they are reported as INFO, not scored — the stock
# config (password auth on, root login prohibit-password) is an OS default.
_sshd_query() {
    run_root sshd -G
    [[ $ROOT_CMD_STATUS -ne 0 ]] && run_root sshd -T
    local cfg="$ROOT_CMD_OUTPUT" cfg_status=$ROOT_CMD_STATUS
    run_root launchctl print system/com.openssh.sshd
    SSHD_ENABLED=0
    [[ $ROOT_CMD_STATUS -eq 0 ]] && SSHD_ENABLED=1
    ROOT_CMD_OUTPUT="$cfg"; ROOT_CMD_STATUS=$cfg_status
}

_sshd_inactive_result() {
    local control="$1" key="$2" mscp_id="$3" line=""
    line=$(print -r -- "$ROOT_CMD_OUTPUT" | grep -i "^$key " | head -1)
    add_audit_result --category 'SSH Server & Client Hardening' --control "$control" \
        --status INFO --severity Informational \
        --current "Remote Login is off; effective setting if enabled: ${line:-$key not reported}" \
        --recommended 'Harden before enabling Remote Login' --cis-macos 'N/A' --mscp "$mscp_id" \
        --recommendation 'Not scored while Remote Login (sshd) is off. Before turning it on, set this in /etc/ssh/sshd_config.d/ and re-run the audit.'
}

check_sshd_password_auth() {
    write_section_banner 'SSH Server & Client Hardening - sshd Password Authentication'
    _sshd_query

    if [[ $ROOT_CMD_STATUS -ne 0 ]]; then
        add_audit_result --category 'SSH Server & Client Hardening' --control 'sshd Password Authentication' \
            --status WARN --severity Low --current 'sshd not available for query' \
            --recommended 'PasswordAuthentication no' \
            --cis 'CIS 5.9' --nist 'IA-2, IA-5' --cis-macos 'N/A' --mscp 'auth_ssh_password_authentication_disable' \
            --recommendation 'Unable to query sshd effective configuration; verify manually with "sshd -G".'
        return
    fi
    if (( ! SSHD_ENABLED )); then
        _sshd_inactive_result 'sshd Password Authentication' passwordauthentication 'auth_ssh_password_authentication_disable'
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
                --nis2 'Art.21(2)(i)' --nsa 'NSA/CISA SSH Hardening Guidance' --cis-macos 'N/A' --mscp 'auth_ssh_password_authentication_disable' \
                --recommendation 'No action required.'
            ;;
        yes)
            add_audit_result --category 'SSH Server & Client Hardening' --control 'sshd Password Authentication' \
                --status WARN --severity High --current 'PasswordAuthentication yes' \
                --recommended 'PasswordAuthentication no' \
                --cis 'CIS 5.9' --nist 'IA-2, IA-5' --mitre 'T1110 (Brute Force)' --iso27001 'A.8.5' \
                --nis2 'Art.21(2)(i)' --nsa 'NSA/CISA SSH Hardening Guidance' --cis-macos 'N/A' --mscp 'auth_ssh_password_authentication_disable' \
                --recommendation 'Set "PasswordAuthentication no" in /etc/ssh/sshd_config and rely on key-based authentication.'
            ;;
        *)
            add_audit_result --category 'SSH Server & Client Hardening' --control 'sshd Password Authentication' \
                --status WARN --severity Low --current "Query failed or unrecognized output: $line" \
                --recommended 'PasswordAuthentication no' \
                --cis 'CIS 5.9' --nist 'IA-2, IA-5' --cis-macos 'N/A' --mscp 'auth_ssh_password_authentication_disable' \
                --recommendation 'Unable to determine PasswordAuthentication setting; verify manually with "sshd -G".'
            ;;
    esac
}

check_sshd_permit_root_login() {
    _sshd_query

    if [[ $ROOT_CMD_STATUS -ne 0 ]]; then
        add_audit_result --category 'SSH Server & Client Hardening' --control 'sshd Permit Root Login' \
            --status WARN --severity Low --current 'sshd not available for query' \
            --recommended 'PermitRootLogin no' \
            --cis 'CIS 5.9' --nist 'AC-6, IA-2' --cis-macos 'N/A' --mscp 'os_sshd_permit_root_login_configure' \
            --recommendation 'Unable to query sshd effective configuration; verify manually with "sshd -G".'
        return
    fi
    if (( ! SSHD_ENABLED )); then
        _sshd_inactive_result 'sshd Permit Root Login' permitrootlogin 'os_sshd_permit_root_login_configure'
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
            --nis2 'Art.21(2)(i)' --cis-macos 'N/A' --mscp 'os_sshd_permit_root_login_configure' \
            --recommendation 'No action required.'
    else
        add_audit_result --category 'SSH Server & Client Hardening' --control 'sshd Permit Root Login' \
            --status FAIL --severity High --current "PermitRootLogin ${value:-unknown}" \
            --recommended 'PermitRootLogin no' \
            --cis 'CIS 5.9' --nist 'AC-6, IA-2' --mitre 'T1078.001 (Default Accounts)' --iso27001 'A.8.5' \
            --nis2 'Art.21(2)(i)' --cis-macos 'N/A' --mscp 'os_sshd_permit_root_login_configure' \
            --recommendation 'Set "PermitRootLogin no" in /etc/ssh/sshd_config.'
    fi
}

check_sshd_weak_ciphers() {
    _sshd_query

    if [[ $ROOT_CMD_STATUS -ne 0 ]]; then
        add_audit_result --category 'SSH Server & Client Hardening' --control 'sshd Weak Ciphers' \
            --status WARN --severity Low --current 'sshd not available for query' \
            --recommended 'No weak (3des-cbc/arcfour/*-cbc) ciphers configured' \
            --cis 'CIS 5.9' --nist 'SC-13' --cis-macos 'N/A' --mscp 'os_sshd_channel_timeout_configure' \
            --recommendation 'Unable to query sshd effective configuration; verify manually with "sshd -G".'
        return
    fi
    if (( ! SSHD_ENABLED )); then
        _sshd_inactive_result 'sshd Weak Ciphers' ciphers 'N/A'
        return
    fi

    local line ciphers_lower
    line=$(print -r -- "$ROOT_CMD_OUTPUT" | grep -i '^ciphers' | head -1)

    if [[ -z "$line" ]]; then
        add_audit_result --category 'SSH Server & Client Hardening' --control 'sshd Weak Ciphers' \
            --status PASS --severity Medium --current 'No explicit Ciphers directive (Apple default ciphers apply)' \
            --recommended 'No weak (3des-cbc/arcfour/*-cbc) ciphers configured' \
            --cis 'CIS 5.9' --nist 'SC-13' --mitre 'T1040 (Network Sniffing)' --iso27001 'A.8.24' \
            --nis2 'Art.21(2)(h)' --cis-macos 'N/A' --mscp 'os_sshd_channel_timeout_configure' \
            --recommendation 'No action required.'
        return
    fi

    ciphers_lower="${line:l}"
    if [[ "$ciphers_lower" == *"3des-cbc"* || "$ciphers_lower" == *"arcfour"* || "$ciphers_lower" == *"-cbc"* ]]; then
        add_audit_result --category 'SSH Server & Client Hardening' --control 'sshd Weak Ciphers' \
            --status WARN --severity Medium --current "$line" \
            --recommended 'No weak (3des-cbc/arcfour/*-cbc) ciphers configured' \
            --cis 'CIS 5.9' --nist 'SC-13' --mitre 'T1040 (Network Sniffing)' --iso27001 'A.8.24' \
            --nis2 'Art.21(2)(h)' --cis-macos 'N/A' --mscp 'os_sshd_channel_timeout_configure' \
            --recommendation 'Restrict to AES-GCM/ChaCha20 AEAD ciphers via "Ciphers" in /etc/ssh/sshd_config.'
    else
        add_audit_result --category 'SSH Server & Client Hardening' --control 'sshd Weak Ciphers' \
            --status PASS --severity Medium --current "$line" \
            --recommended 'No weak (3des-cbc/arcfour/*-cbc) ciphers configured' \
            --cis 'CIS 5.9' --nist 'SC-13' --mitre 'T1040 (Network Sniffing)' --iso27001 'A.8.24' \
            --nis2 'Art.21(2)(h)' --cis-macos 'N/A' --mscp 'os_sshd_channel_timeout_configure' \
            --recommendation 'No action required.'
    fi
}

check_ssh_client_strict_host_key_checking() {
    if [[ -z "$CONSOLE_USER" ]]; then
        add_audit_result --category 'SSH Server & Client Hardening' --control 'SSH Client Strict Host Key Checking' \
            --status WARN --severity Low --current 'No console user detected' \
            --recommended 'N/A' --cis-macos 'N/A' --mscp 'N/A' \
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
            --recommended 'N/A' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'Informational only. No client-side SSH config overrides are in effect.'
        return
    fi

    if print -r -- "$RUN_AS_USER_OUTPUT" | grep -Eqi 'StrictHostKeyChecking[[:space:]]+no'; then
        add_audit_result --category 'SSH Server & Client Hardening' --control 'SSH Client Strict Host Key Checking' \
            --status WARN --severity Low --current 'StrictHostKeyChecking no found in ~/.ssh/config' \
            --recommended 'StrictHostKeyChecking not overridden to "no"' \
            --cis 'CIS 5.9' --nist 'SC-8' --mitre 'T1557 (Adversary-in-the-Middle)' --iso27001 'A.8.24' \
            --nis2 'Art.21(2)(h)' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'Remove or correct that override — it disables protection against host-key-spoofing MITM attacks.'
    else
        add_audit_result --category 'SSH Server & Client Hardening' --control 'SSH Client Strict Host Key Checking' \
            --status PASS --severity Low --current 'No StrictHostKeyChecking override found' \
            --recommended 'StrictHostKeyChecking not overridden to "no"' \
            --cis 'CIS 5.9' --nist 'SC-8' --mitre 'T1557 (Adversary-in-the-Middle)' --iso27001 'A.8.24' \
            --nis2 'Art.21(2)(h)' --cis-macos 'N/A' --mscp 'N/A' \
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
            --nis2 'Art.21(2)(h)' --nsa 'NSA/CISA PKI Guidance' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'No action required.'
        return
    fi

    local count
    count=$(print -r -- "$ROOT_CMD_OUTPUT" | grep -c '^[[:space:]]*[0-9]\+\.')

    add_audit_result --category 'Cryptography & Certificate Trust' --control 'System Trust Settings Overrides' \
        --status WARN --severity Medium --current "$count admin-level trust setting override(s) found" \
        --recommended 'No admin-level trust setting overrides' \
        --cis 'CIS 3.10' --nist 'SC-17' --mitre 'T1553.004 (Install Root Certificate)' --iso27001 'A.8.24' \
        --nis2 'Art.21(2)(h)' --nsa 'NSA/CISA PKI Guidance' --cis-macos 'N/A' --mscp 'N/A' \
        --recommendation 'Review each overridden root/intermediate CA trust setting — an unexpected trusted root is a MITM risk.'
}

check_login_keychain_lock_on_sleep() {
    if [[ -z "$CONSOLE_USER" ]]; then
        add_audit_result --category 'Cryptography & Certificate Trust' --control 'Login Keychain Lock on Sleep' \
            --status WARN --severity Low --current 'No console user detected' \
            --recommended 'N/A' --cis-macos 'N/A' --mscp 'N/A' \
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
            --recommended 'N/A' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'Unable to determine login keychain settings; verify manually with "security show-keychain-info".'
        return
    fi

    if [[ "$RUN_AS_USER_OUTPUT" == *"lock-on-sleep"* ]]; then
        add_audit_result --category 'Cryptography & Certificate Trust' --control 'Login Keychain Lock on Sleep' \
            --status PASS --severity Medium --current "$RUN_AS_USER_OUTPUT" \
            --recommended 'lock-on-sleep enabled' \
            --cis 'CIS 3.10' --nist 'SC-28' --iso27001 'A.8.24' --nis2 'Art.21(2)(h)' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'No action required.'
    else
        add_audit_result --category 'Cryptography & Certificate Trust' --control 'Login Keychain Lock on Sleep' \
            --status WARN --severity Medium --current "$RUN_AS_USER_OUTPUT" \
            --recommended 'lock-on-sleep enabled' \
            --cis 'CIS 3.10' --nist 'SC-28' --iso27001 'A.8.24' --nis2 'Art.21(2)(h)' --cis-macos 'N/A' --mscp 'N/A' \
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
        --recommended 'N/A' --cis-macos 'N/A' --mscp 'N/A' \
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
            --nis2 'Art.21(2)(f)' --nsa 'NSA/CISA Logging Guidance' --cis-macos 'CIS-macOS 3.1' --mscp 'audit_auditd_enabled' \
            --recommendation 'No action required.'
    else
        add_audit_result --category 'Audit, Logging & Telemetry' --control 'Audit Subsystem Enabled' \
            --status FAIL --severity Medium --current 'auditd is not running' \
            --recommended 'auditd is running' \
            --cis 'CIS 8.1' --nist 'AU-2, AU-12' --mitre 'T1562.008 (Disable Cloud Logs)' --iso27001 'A.8.15' \
            --nis2 'Art.21(2)(f)' --nsa 'NSA/CISA Logging Guidance' --cis-macos 'CIS-macOS 3.1' --mscp 'audit_auditd_enabled' \
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
            --nis2 'Art.21(2)(f)' --cis-macos 'CIS-macOS 3.2' --mscp 'audit_flags_aa_configure' \
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
            --nis2 'Art.21(2)(f)' --cis-macos 'CIS-macOS 3.2' --mscp 'audit_flags_aa_configure' \
            --recommendation 'No action required.'
    else
        add_audit_result --category 'Audit, Logging & Telemetry' --control 'Audit Control Flags' \
            --status WARN --severity Medium --current "${flags_line:-No flags line found in $ac_path}" \
            --recommended 'flags line includes the aa class' \
            --cis 'CIS 8.1' --nist 'AU-2' --mitre 'T1078' --iso27001 'A.8.15' \
            --nis2 'Art.21(2)(f)' --cis-macos 'CIS-macOS 3.2' --mscp 'audit_flags_aa_configure' \
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
            --cis 'CIS 8.11' --nist 'SI-4' --iso27001 'A.8.16' --nis2 'Art.21(2)(f)' --cis-macos 'CIS-macOS 2.6.3.1' --mscp 'system_settings_diagnostics_reports_disable' \
            --recommendation 'Disable in System Settings > Privacy & Security > Analytics & Improvements if sending device diagnostics off-network is against policy.'
    else
        add_audit_result --category 'Audit, Logging & Telemetry' --control 'Diagnostics Auto-Submit' \
            --status PASS --severity Low --current "AutoSubmit=$autosubmit" \
            --recommended 'AutoSubmit=0' \
            --cis 'CIS 8.11' --nist 'SI-4' --iso27001 'A.8.16' --nis2 'Art.21(2)(f)' --cis-macos 'CIS-macOS 2.6.3.1' --mscp 'system_settings_diagnostics_reports_disable' \
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
    # Newest Apple update in the system install log (softwareupdated /
    # bootinstalld entries; readable without root). `softwareupdate
    # --history` is the fallback: in a real sudo run on Tahoe it returned
    # nothing parseable, although the same command worked unprivileged.
    local date_token=""
    local history_plist="${INSTALL_HISTORY_PLIST:-/Library/Receipts/InstallHistory.plist}"
    if [[ -r "$history_plist" ]]; then
        # Weekly background data (XProtectPlistConfigData, XProtectPayloads,
        # Gatekeeper/MRT config) also arrives via softwareupdated and would
        # make an unpatched Mac look current, so it is excluded.
        date_token=$(plutil -p "$history_plist" 2>/dev/null | awk '
            /"date" =>/ { d = $3 }
            /"displayName" =>/ { n = $0 }
            /"processName" => "(softwareupdated|bootinstalld)"/ {
                if (n !~ /XProtect|ConfigData|Payloads|Gatekeeper|MRT/) print d
            }' | sort | tail -1)
    fi
    run_root softwareupdate --history

    # Real "softwareupdate --history" output (confirmed live): a header
    # line, a dashes separator line, then one data row per update in
    # chronological order (oldest first), each with a date column
    # formatted "YYYY-MM-DD, HH:MM:SS" — the date token itself carries a
    # trailing comma, split from the time as a separate whitespace token.
    # Newest date anywhere in the history, not the last line: the list is
    # oldest-first today (verified live) but that order is undocumented.
    [[ -z "$date_token" ]] && date_token=$(print -r -- "$ROOT_CMD_OUTPUT" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' | sort | tail -1)
    local epoch=""
    if [[ -n "$date_token" ]]; then
        epoch=$(date -j -f "%Y-%m-%d" "$date_token" +%s 2>/dev/null)
    fi

    if [[ -z "$epoch" ]]; then
        add_audit_result --category 'Software Update & Patch Compliance' --control 'Recent Update History' \
            --status WARN --severity Medium \
            --current 'Unable to determine last update date from local history — offline check only, does not query Apple servers' \
            --recommended 'Last update within 45 days' \
            --cis 'CIS 7.3' --nist 'SI-2' --cis-macos 'CIS-macOS 1.1' --mscp 'system_settings_softwareupdate_current' \
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
            --nis2 'Art.21(2)(e)' --nsa 'NSA/CISA Patch Management Guidance' --cis-macos 'CIS-macOS 1.1' --mscp 'system_settings_softwareupdate_current' \
            --recommendation 'No action required.'
    else
        add_audit_result --category 'Software Update & Patch Compliance' --control 'Recent Update History' \
            --status WARN --severity Medium --current "Last update: $date_token ($days_since day(s) ago)" \
            --recommended 'Last update within 45 days' \
            --cis 'CIS 7.3' --nist 'SI-2' --mitre 'T1210 (Exploitation of Remote Services)' --iso27001 'A.8.8' \
            --nis2 'Art.21(2)(e)' --nsa 'NSA/CISA Patch Management Guidance' --cis-macos 'CIS-macOS 1.1' --mscp 'system_settings_softwareupdate_current' \
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
        --recommended 'N/A' --cis-macos 'CIS-macOS 1.5' --mscp 'N/A' \
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
        --cis 'CIS 12.5' --nist 'CM-8' --iso27001 'A.8.9' --nis2 'Art.21(2)(a)' --cis-macos 'N/A' --mscp 'N/A' \
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
        --recommended 'N/A' --cis-macos 'N/A' --mscp 'N/A' \
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
    local f="$1" expected_owner="${2:-root}" target="" info="" owner="" mode="" acl=""
    for target in "$f" "${f:h}"; do
        info=$(stat -f '%Su %Lp' "$target" 2>/dev/null) || continue
        owner="${info% *}"; mode="${info#* }"
        # Digits only before arithmetic (project rule), then the octal test.
        if [[ "$mode" == <-> ]] && (( 8#$mode & 8#022 )); then
            print -r -- "$target writable by group/other (mode $mode)"; return 0
        fi
        if [[ "$owner" != root && "$owner" != "$expected_owner" ]]; then
            print -r -- "$target owned by $owner"; return 0
        fi
        if acl=$(_acl_write_grantees "$target" "$expected_owner"); then
            print -r -- "$target writable through an ACL ($acl)"; return 0
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
        --iso27001 'A.8.19' --nis2 'Art.21(2)(d)' --cis-macos 'N/A' --mscp 'N/A')

    if [[ ${#PERSIST_STRONG[@]} -gt 0 ]]; then
        add_audit_result --category "$PERSIST_CATEGORY" --control "$control_label" \
            --status FAIL --severity High --current "${(j: | :)PERSIST_STRONG}" \
            --details "${(F)PERSIST_STRONG}${PERSIST_WEAK:+$NL${(F)PERSIST_WEAK}}" "${fw[@]}" \
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
            --cis-macos 'N/A' --mscp 'N/A' \
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
        run_prefetched btm sfltool dumpbtm
        BTM_DUMP="$ROOT_CMD_OUTPUT"
        BTM_DUMP_STATUS=$ROOT_CMD_STATUS
    fi
    return $BTM_DUMP_STATUS
}

check_login_items_inventory() {
    load_btm_dump
    local ROOT_CMD_OUTPUT="$BTM_DUMP" ROOT_CMD_STATUS=$BTM_DUMP_STATUS

    if [[ "$ROOT_CMD_STATUS" -ne 0 ]]; then
        add_audit_result --category 'Persistence Mechanisms & Auto-Runs' --control 'Login Items & Background Task Inventory' \
            --status WARN --severity Low --current "sfltool query failed: $ROOT_CMD_OUTPUT" \
            --recommended 'N/A' --cis-macos 'N/A' --mscp 'N/A' \
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
        --recommended 'N/A' --cis-macos 'N/A' --mscp 'N/A' \
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
            --details "${(F)hi}${lo:+$NL${(F)lo}}" "${fw[@]}" --recommendation "$recommendation"
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
            keys+=("$user: $n key(s) in ${f:t} — $(grep -vE '^[[:space:]]*(#|$)' "$f" | awk '{print $NF}' | head -5 | paste -sd ',' - | sed 's/,/, /g')")
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
        --nis2 'Art.21(2)(d)' --cis-macos 'N/A' --mscp 'N/A'
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
        --recommended 'N/A' --cis 'CIS 2.1, 2.7' --nist 'CM-8' --iso27001 'A.5.9' --cis-macos 'N/A' --mscp 'N/A' \
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
            --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation "Unable to verify permissions for $dir; check manually with \"stat -f '%Lp' $dir\"."
        return
    fi

    local mode="$ROOT_CMD_OUTPUT" acl=""
    acl=$(_acl_write_grantees "$dir" root) || acl=""

    if [[ -n "$acl" ]] || _mode_group_or_other_writable "$mode"; then
        add_audit_result --category 'Privilege Escalation: File & Directory Permissions' --control "$control_name" \
            --status FAIL --severity Critical --current "$dir mode $mode${acl:+; ACL grants write: $acl}" \
            --recommended 'No group/other write bit' \
            --cis 'CIS 5.1' --nist 'AC-6, CM-6' --mitre 'T1574.010 (Services File Permissions Weakness)' --iso27001 'A.8.3' \
            --nis2 'Art.21(2)(d)' --nsa 'NSA/CISA macOS Hardening Guidance' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation "sudo chmod go-w $dir (and remove any ACL write entries: sudo chmod -N $dir) — a world/group-writable LaunchDaemons or LaunchAgents directory lets any local user plant a persistent root-level launch item."
    else
        add_audit_result --category 'Privilege Escalation: File & Directory Permissions' --control "$control_name" \
            --status PASS --severity Critical --current "$dir mode $mode" \
            --recommended 'No group/other write bit' \
            --cis 'CIS 5.1' --nist 'AC-6, CM-6' --mitre 'T1574.010 (Services File Permissions Weakness)' --iso27001 'A.8.3' \
            --nis2 'Art.21(2)(d)' --nsa 'NSA/CISA macOS Hardening Guidance' --cis-macos 'N/A' --mscp 'N/A' \
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
    dirs=(${(us.:.)path_string})   # unique: inherited PATHs often repeat entries

    local -a writable=()
    local scanned=0 dir

    for dir in "${dirs[@]}"; do
        [[ -z "$dir" || ! -d "$dir" ]] && continue
        scanned=$((scanned + 1))

        run_root stat -f '%Su %Lp' "$dir"
        [[ $ROOT_CMD_STATUS -ne 0 ]] && continue

        local owner="${ROOT_CMD_OUTPUT%% *}" mode="${ROOT_CMD_OUTPUT##* }"
        [[ "$mode" == <-> ]] || continue
        local last3="${mode: -3}"
        local owner_digit="${last3:0:1}"

        local is_writable=0
        if [[ "$owner" != "root" && "$owner_digit" == [2367] ]]; then is_writable=1; fi
        _mode_group_or_other_writable "$mode" && is_writable=1
        _acl_write_grantees "$dir" root >/dev/null && is_writable=1

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
            --nis2 'Art.21(2)(d)' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'Run "sudo chmod go-w <dir>" on each listed directory, or remove it from $PATH — any user-writable $PATH entry ahead of /usr/bin is a classic PATH-hijack vector.'
    else
        add_audit_result --category 'Privilege Escalation: File & Directory Permissions' --control 'Writable PATH Directories' \
            --status PASS --severity High --current "$scanned director(y/ies) scanned, none writable by non-root" \
            --recommended 'No PATH directory writable by a non-root user' \
            --cis 'CIS 5.1' --nist 'AC-6, CM-6' --mitre 'T1574.007 (PATH Interception)' --iso27001 'A.8.3' \
            --nis2 'Art.21(2)(d)' --cis-macos 'N/A' --mscp 'N/A' \
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
        # /usr/local is not system: it is Homebrew's prefix on Intel Macs
        # and often user-writable, so a SUID binary there must be reported.
        /usr/local/*) return 1 ;;
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
            --nis2 'Art.21(2)(d)' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'Review each non-system SUID/SGID binary; confirm it is expected and from a trusted vendor.'
    else
        add_audit_result --category 'Privilege Escalation: File & Directory Permissions' --control 'SUID/SGID Binary Audit' \
            --status PASS --severity High --current "$total SUID/SGID binaries scanned" \
            --recommended 'No SUID/SGID binaries outside /usr, /bin, /sbin, /System' \
            --cis 'CIS 5.1' --nist 'AC-6, CM-6' --mitre 'T1548.001 (Setuid and Setgid)' --iso27001 'A.8.3' \
            --nis2 'Art.21(2)(d)' --cis-macos 'N/A' --mscp 'N/A' \
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
        add_audit_result --category 'Privilege Escalation: File & Directory Permissions' --control "$control" \
            --status PASS --severity "$severity" --current "No world-writable directories under $scanned" "${fw[@]}" \
            --recommendation 'No action required.'
    else
        add_audit_result --category 'Privilege Escalation: File & Directory Permissions' --control "$control" \
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
        add_audit_result --category 'Privilege Escalation: File & Directory Permissions' --control 'Home Folders Secure' \
            --status PASS --severity Medium --current 'All home folders restrict other users' "${fw[@]}" \
            --recommendation 'No action required.'
    else
        local -a described
        local d
        for d in "${insecure[@]}"; do
            described+=("$d ($(stat -f '%Sp' "$d" 2>/dev/null))")
        done
        add_audit_result --category 'Privilege Escalation: File & Directory Permissions' --control 'Home Folders Secure' \
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
            --nis2 'Art.21(2)(d)' --nsa 'NSA/CISA macOS Hardening Guidance' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'sudo launchctl unsetenv DYLD_INSERT_LIBRARIES — a globally-set DYLD_INSERT_LIBRARIES forces code injection into every subsequently launched dynamically-linked process.'
    else
        add_audit_result --category 'Dylib Hijacking & Code Injection' --control 'DYLD_INSERT_LIBRARIES Global Env' \
            --status PASS --severity Critical --current 'unset' \
            --recommended 'unset' \
            --cis 'CIS 2.7' --nist 'SI-7, CM-7' --mitre 'T1574.006 (Dynamic Linker Hijacking)' --iso27001 'A.8.19' \
            --nis2 'Art.21(2)(d)' --nsa 'NSA/CISA macOS Hardening Guidance' --cis-macos 'N/A' --mscp 'N/A' \
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

    local mode="$ROOT_CMD_OUTPUT" acl=""
    acl=$(_acl_write_grantees "$dir" root) || acl=""

    if [[ -n "$acl" ]] || _mode_group_or_other_writable "$mode"; then
        add_audit_result --category 'Dylib Hijacking & Code Injection' --control 'Writable Dylib Search Paths' \
            --status FAIL --severity High --current "$dir mode $mode${acl:+; ACL grants write: $acl}" \
            --recommended 'No group/other write bit' \
            --cis 'CIS 2.7' --nist 'SI-7, CM-7' --mitre 'T1574.006 (Dynamic Linker Hijacking)' --iso27001 'A.8.19' \
            --nis2 'Art.21(2)(d)' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation "sudo chmod go-w $dir — a writable systemwide library search path lets any local user plant a hijacked dylib for any process that searches it."
    else
        add_audit_result --category 'Dylib Hijacking & Code Injection' --control 'Writable Dylib Search Paths' \
            --status PASS --severity High --current "$dir mode $mode" \
            --recommended 'No group/other write bit' \
            --cis 'CIS 2.7' --nist 'SI-7, CM-7' --mitre 'T1574.006 (Dynamic Linker Hijacking)' --iso27001 'A.8.19' \
            --nis2 'Art.21(2)(d)' --cis-macos 'N/A' --mscp 'N/A' \
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
        --recommended 'N/A' --cis-macos 'N/A' --mscp 'N/A' \
        --recommendation 'Informational only.'
}

# Electron fuses: build-time switches compiled into the Electron framework
# right after the sentinel "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX", then a
# version byte, a length byte and one byte per fuse ('1' on, '0' off,
# 'r' removed). With RunAsNode / NodeOptions / --inspect fuses on, anyone
# who can run code as the user can make the app execute arbitrary
# JavaScript that inherits the app's TCC grants (camera, mic, Full Disk
# Access) — the CVE-2025-54871 class. Read with stock grep/dd/od only.
typeset -ga ELECTRON_FUSE_NAMES
ELECTRON_FUSE_NAMES=(RunAsNode EnableCookieEncryption EnableNodeOptionsEnvironmentVariable
    EnableNodeCliInspectArguments EnableEmbeddedAsarIntegrityValidation OnlyLoadAppFromAsar)

# Prints "name=on|off|removed" per fuse, or returns 1 when the framework
# has no fuse wire (very old Electron) or can't be read.
_electron_fuses() {
    local framework="$1" offset="" len=0 i=0 b=""
    local -a bytes
    offset=$(LC_ALL=C grep -obUa 'dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX' "$framework" 2>/dev/null | head -1 | cut -d: -f1)
    [[ "$offset" == <-> ]] || return 1
    bytes=($(dd if="$framework" bs=1 skip=$(( offset + 33 )) count=16 2>/dev/null | od -An -tu1))
    len="${bytes[1]:-0}"
    for (( i = 1; i <= len && i <= ${#ELECTRON_FUSE_NAMES[@]}; i++ )); do
        b="${bytes[$((i + 1))]:-}"
        case "$b" in
            49) print -r -- "${ELECTRON_FUSE_NAMES[$i]}=on" ;;
            48) print -r -- "${ELECTRON_FUSE_NAMES[$i]}=off" ;;
            114) print -r -- "${ELECTRON_FUSE_NAMES[$i]}=removed" ;;
            *) print -r -- "${ELECTRON_FUSE_NAMES[$i]}=unknown" ;;
        esac
    done
}

_electron_app_dirs() {
    local entry="" home=""
    print -rl -- /Applications/*.app(N/) /Applications/*/*.app(N/)
    for entry in "${(@f)$(_local_user_homes 2>/dev/null)}"; do
        [[ -z "$entry" ]] && continue
        home="${entry#*$'\t'}"
        print -rl -- "$home"/Applications/*.app(N/)
    done
}

check_electron_node_fuses() {
    local app="" framework="" fuses="" exposed=""
    local -a apps vulnerable hardened
    apps=("${(@f)$(_electron_app_dirs)}"); apps=(${apps:#})
    for app in "${apps[@]}"; do
        framework="$app/Contents/Frameworks/Electron Framework.framework/Electron Framework"
        [[ -e "$framework" ]] || continue
        fuses=$(_electron_fuses "$framework") || { vulnerable+=("${app:t}: no fuse wire (pre-fuses Electron, RunAsNode always available)"); continue; }
        exposed=$(print -r -- "$fuses" | grep -E '^(RunAsNode|EnableNodeOptionsEnvironmentVariable|EnableNodeCliInspectArguments)=on$' | cut -d= -f1 | paste -sd ',' -)
        if [[ -n "$exposed" ]]; then
            vulnerable+=("${app:t}: ${exposed//,/, } on")
        else
            hardened+=("${app:t}")
        fi
    done

    local -a fw
    fw=(--recommended 'Electron apps ship with RunAsNode, NODE_OPTIONS and --inspect fuses disabled'
        --cis 'CIS 2.5' --nist 'SI-7, AC-6' --mitre 'T1218 (System Binary Proxy Execution), T1548 (Abuse Elevation Control Mechanism)'
        --iso27001 'A.8.19' --nis2 'Art.21(2)(e)' --cis-macos 'N/A' --mscp 'N/A')
    if [[ ${#vulnerable[@]} -gt 0 ]]; then
        add_audit_result --category 'Dylib Hijacking & Code Injection' --control 'Electron Apps with Node Execution Fuses Enabled' \
            --status WARN --severity Medium --current "${#vulnerable[@]} of $(( ${#vulnerable[@]} + ${#hardened[@]} )) Electron app(s) can be driven as a Node.js runtime" \
            --details "${(F)vulnerable}" "${fw[@]}" \
            --recommendation 'Update the listed apps (vendors increasingly ship hardened fuses), and avoid granting them Full Disk Access, camera, microphone or Accessibility: local code can run inside them via ELECTRON_RUN_AS_NODE / --inspect and inherit those grants (CVE-2025-54871 class). Report unhardened builds to the vendor.'
    elif [[ ${#hardened[@]} -gt 0 ]]; then
        add_audit_result --category 'Dylib Hijacking & Code Injection' --control 'Electron Apps with Node Execution Fuses Enabled' \
            --status PASS --severity Medium --current "${#hardened[@]} Electron app(s), all with Node execution fuses disabled" \
            --details "${(F)hardened}" "${fw[@]}" --recommendation 'No action required.'
    else
        add_audit_result --category 'Dylib Hijacking & Code Injection' --control 'Electron Apps with Node Execution Fuses Enabled' \
            --status PASS --severity Medium --current 'No Electron apps installed' "${fw[@]}" --recommendation 'No action required.'
    fi
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
            --nis2 'Art.21(2)(h)' --nsa 'NSA/CISA Credential Hardening Guidance' --cis-macos 'N/A' --mscp 'N/A' \
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
        # Only actual private keys: known_hosts, config and authorized_keys
        # are meant to be readable (known_hosts is 644 by default) and were
        # reported as over-permissive keys before.
        run_as_user head -c 64 "$k"
        [[ "$RUN_AS_USER_OUTPUT" == *"PRIVATE KEY"* ]] || continue
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
            --nis2 'Art.21(2)(h)' --nsa 'NSA/CISA Credential Hardening Guidance' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'Run "chmod 600" on each listed private key.'
    else
        add_audit_result --category 'Credential Exposure & Secret Leaks' --control 'SSH Private Key Permissions' \
            --status PASS --severity High --current "$total key(s) checked" \
            --recommended 'All private keys mode 600' \
            --cis 'CIS 3.11' --nist 'IA-5, SC-28' --mitre 'T1552.004 (Private Keys)' --iso27001 'A.8.24' \
            --nis2 'Art.21(2)(h)' --nsa 'NSA/CISA Credential Hardening Guidance' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'No action required.'
    fi
}

check_ssh_private_key_permissions() {
    write_section_banner 'Credential Exposure & Secret Leaks - SSH Private Key Permissions'
    if [[ -z "$CONSOLE_USER" ]]; then
        add_audit_result --category 'Credential Exposure & Secret Leaks' --control 'SSH Private Key Permissions' \
            --status WARN --severity Low --current 'No console user detected' \
            --recommended 'N/A' --cis-macos 'N/A' --mscp 'N/A' \
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
            --nis2 'Art.21(2)(h)' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'Prefer short-lived SSO/OIDC tokens over long-lived static credential files where the CLI supports it; ensure file permissions are 600.'
    else
        add_audit_result --category 'Credential Exposure & Secret Leaks' --control 'Cloud CLI Credential Files' \
            --status PASS --severity Medium --current 'No cloud CLI credential files found' \
            --recommended 'No long-lived cloud CLI credential files' \
            --cis 'CIS 3.11' --nist 'IA-5' --mitre 'T1552.001 (Credentials in Files)' --iso27001 'A.8.24' \
            --nis2 'Art.21(2)(h)' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'No action required.'
    fi
}

check_cloud_cli_credential_files() {
    if [[ -z "$CONSOLE_USER" ]]; then
        add_audit_result --category 'Credential Exposure & Secret Leaks' --control 'Cloud CLI Credential Files' \
            --status WARN --severity Low --current 'No console user detected' \
            --recommended 'N/A' --cis-macos 'N/A' --mscp 'N/A' \
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
            --nis2 'Art.21(2)(h)' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'Rotate any credential that may have been typed into a shell prompt and clear it from history.'
    else
        add_audit_result --category 'Credential Exposure & Secret Leaks' --control 'Shell History Secret Sweep' \
            --status PASS --severity High --current 'No secret-like patterns found in recent shell history' \
            --recommended 'No secret-like patterns in recent shell history' \
            --cis 'CIS 3.11' --nist 'IA-5' --mitre 'T1552.001 (Credentials in Files)' --iso27001 'A.8.24' \
            --nis2 'Art.21(2)(h)' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'No action required.'
    fi
}

check_shell_history_secret_sweep() {
    if [[ -z "$CONSOLE_USER" ]]; then
        add_audit_result --category 'Credential Exposure & Secret Leaks' --control 'Shell History Secret Sweep' \
            --status WARN --severity Low --current 'No console user detected' \
            --recommended 'N/A' --cis-macos 'N/A' --mscp 'N/A' \
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
            --nis2 'Art.21(2)(h)' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'Relocate genuine secrets into Keychain or a secrets manager; delete stray exports.'
    else
        add_audit_result --category 'Credential Exposure & Secret Leaks' --control 'Sensitive Filename Sweep' \
            --status PASS --severity Medium --current 'No sensitive filenames found in Desktop/Downloads' \
            --recommended 'No sensitive filenames in Desktop/Downloads' \
            --cis 'CIS 3.11' --nist 'IA-5' --mitre 'T1552.001 (Credentials in Files)' --iso27001 'A.8.24' \
            --nis2 'Art.21(2)(h)' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'No action required.'
    fi
}

check_sensitive_filename_sweep() {
    if [[ -z "$CONSOLE_USER" ]]; then
        add_audit_result --category 'Credential Exposure & Secret Leaks' --control 'Sensitive Filename Sweep' \
            --status WARN --severity Low --current 'No console user detected' \
            --recommended 'N/A' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'Re-run interactively at a console login session to evaluate sensitive filenames.'
        return
    fi
    _sensitive_filename_sweep_check "$(eval echo ~$CONSOLE_USER)"
}

# ---- 28-screen-lock.zsh ----
#
# Domain 19: Screen Lock & Physical Access

# The screen-lock password setting stopped living in the user's
# com.apple.screensaver askForPassword/askForPasswordDelay keys years ago
# (verified live on Tahoe: both keys absent while `sysadminctl
# -screenLock status`, run as the user, reports "screenLock delay is
# immediate"). Reading the stale keys reported a FAIL on Macs that lock
# immediately. Sources, in order: an MDM profile, sysadminctl as the
# console user, the legacy key if a Mac still has it; otherwise WARN as
# undeterminable, never a guessed FAIL. Prints "<delay-seconds|off|unknown>
# <source>" (immediate = 0).
_screen_lock_state() {
    local managed="" managed_delay="" legacy="" legacy_delay=""
    managed=$(managed_pref_read com.apple.screensaver askForPassword)
    managed_delay=$(managed_pref_read com.apple.screensaver askForPasswordDelay)
    # Delays reach arithmetic comparisons, and the legacy one comes from a
    # preference file the user controls: accept digits only (anything else
    # is "unknown"), never let it be evaluated as an expression.
    if [[ "$managed" == 1 ]]; then
        [[ -z "$managed_delay" || "$managed_delay" == <-> ]] || { print -r -- "unknown profile"; return 0; }
        print -r -- "${managed_delay:-0} profile"; return 0
    elif [[ "$managed" == 0 ]]; then
        print -r -- "off profile"; return 0
    fi
    if [[ -n "$CONSOLE_USER" ]]; then
        run_as_user sysadminctl -screenLock status
        case "$RUN_AS_USER_OUTPUT" in
            *"screenLock delay is immediate"*) print -r -- "0 sysadminctl"; return 0 ;;
            *"screenLock is off"*) print -r -- "off sysadminctl"; return 0 ;;
        esac
        if [[ "$RUN_AS_USER_OUTPUT" =~ 'screenLock delay is ([0-9]+) seconds' ]]; then
            print -r -- "${match[1]} sysadminctl"; return 0
        fi
        legacy=$(defaults_read_as_user_safe com.apple.screensaver askForPassword '')
        legacy_delay=$(defaults_read_as_user_safe com.apple.screensaver askForPasswordDelay '')
        if [[ "$legacy" == 1 ]]; then
            [[ -z "$legacy_delay" || "$legacy_delay" == <-> ]] || { print -r -- "unknown legacy-preference"; return 0; }
            print -r -- "${legacy_delay:-0} legacy-preference"; return 0
        elif [[ "$legacy" == 0 ]]; then
            print -r -- "off legacy-preference"; return 0
        fi
    fi
    print -r -- "unknown none"
}

check_screensaver_password_required() {
    write_section_banner 'Screen Lock & Physical Access - Screensaver Password'
    local state="" delay="" source=""
    state=$(_screen_lock_state); delay="${state%% *}"; source="${state#* }"
    local -a fw
    fw=(--recommended 'Password required after sleep or screen saver' --cis 'CIS 4.2' --nist 'AC-11'
        --mitre 'T1078 (Valid Accounts)' --iso27001 'A.8.1' --nis2 'Art.21(2)(i)'
        --cis-macos 'CIS-macOS 2.11.2' --mscp 'system_settings_screensaver_password_enforce')
    if [[ "$delay" == unknown ]]; then
        add_audit_result --category 'Screen Lock & Physical Access' --control 'Screensaver Password Requirement' \
            --status WARN --severity Low --current "Unable to determine the screen lock setting${CONSOLE_USER:+ for $CONSOLE_USER}${CONSOLE_USER:-: no console user}" "${fw[@]}" \
            --recommendation 'Verify in System Settings > Lock Screen ("Require password after screen saver begins or display is turned off"), or check with "sysadminctl -screenLock status" as the user.'
    elif [[ "$delay" == off ]]; then
        add_audit_result --category 'Screen Lock & Physical Access' --control 'Screensaver Password Requirement' \
            --status FAIL --severity High --current "Screen lock password not required (source: $source)" "${fw[@]}" \
            --recommendation 'Require a password after the screen saver starts or the display sleeps: System Settings > Lock Screen, or a Screensaver profile payload with askForPassword=true.'
    else
        add_audit_result --category 'Screen Lock & Physical Access' --control 'Screensaver Password Requirement' \
            --status PASS --severity High --current "Password required (source: $source)" "${fw[@]}" \
            --recommendation 'No action required.'
    fi
}

check_screensaver_grace_period() {
    local state="" delay="" source=""
    state=$(_screen_lock_state); delay="${state%% *}"; source="${state#* }"
    local -a fw
    fw=(--recommended '<= 5 seconds' --cis 'CIS 4.2' --nist 'AC-11' --cis-macos 'CIS-macOS 2.11.2'
        --mscp 'system_settings_screensaver_ask_for_password_delay_enforce')
    [[ "$delay" == off || "$delay" == <-> ]] || delay=unknown
    if [[ "$delay" == unknown ]]; then
        add_audit_result --category 'Screen Lock & Physical Access' --control 'Screensaver Password Grace Period' \
            --status WARN --severity Low --current 'Unable to determine the screen lock delay' "${fw[@]}" \
            --recommendation 'Verify in System Settings > Lock Screen, or with "sysadminctl -screenLock status" as the user.'
    elif [[ "$delay" == off ]]; then
        add_audit_result --category 'Screen Lock & Physical Access' --control 'Screensaver Password Grace Period' \
            --status WARN --severity Medium --current "No screen lock (source: $source)" "${fw[@]}" \
            --recommendation 'Turn on the screen lock password (see Screensaver Password Requirement) with a delay of 5 seconds or less.'
    elif [[ "$delay" == <-> ]] && (( delay <= 5 )); then
        add_audit_result --category 'Screen Lock & Physical Access' --control 'Screensaver Password Grace Period' \
            --status PASS --severity Medium --current "$( (( delay == 0 )) && print immediate || print "${delay}s") (source: $source)" "${fw[@]}" \
            --recommendation 'No action required.'
    else
        add_audit_result --category 'Screen Lock & Physical Access' --control 'Screensaver Password Grace Period' \
            --status WARN --severity Medium --current "${delay}s (source: $source)" "${fw[@]}" \
            --recommendation 'Reduce the screen lock grace period to 5 seconds or less in System Settings > Lock Screen, or a Screensaver profile payload with askForPasswordDelay=0.'
    fi
}

check_auto_login_disabled() {
    local value
    value=$(defaults_read_safe '/Library/Preferences/com.apple.loginwindow' 'autoLoginUser' '')

    if [[ -z "$value" ]]; then
        add_audit_result --category 'Screen Lock & Physical Access' --control 'Automatic Login Disabled' \
            --status PASS --severity Critical --current 'No autoLoginUser configured' --recommended 'No autoLoginUser configured' \
            --cis 'CIS 4.2' --nist 'AC-11, IA-2' --mitre 'T1078 (Valid Accounts)' --iso27001 'A.8.1' --nis2 'Art.21(2)(i)' \
            --cis-macos 'CIS-macOS 2.13.3' --mscp 'system_settings_automatic_login_disable' \
            --recommendation 'No action required.'
    else
        add_audit_result --category 'Screen Lock & Physical Access' --control 'Automatic Login Disabled' \
            --status FAIL --severity Critical --current "autoLoginUser=$value" --recommended 'No autoLoginUser configured' \
            --cis 'CIS 4.2' --nist 'AC-11, IA-2' --mitre 'T1078 (Valid Accounts)' --iso27001 'A.8.1' --nis2 'Art.21(2)(i)' \
            --cis-macos 'CIS-macOS 2.13.3' --mscp 'system_settings_automatic_login_disable' \
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
            --nis2 'Art.21(2)(i)' --cis-macos 'CIS-macOS 2.11.4' --mscp 'N/A' \
            --recommendation 'No action required.'
    else
        add_audit_result --category 'Screen Lock & Physical Access' --control 'Login Window Hardening' \
            --status WARN --severity Medium --current "SHOWFULLNAME=$show_full_name" \
            --recommended 'SHOWFULLNAME=1' \
            --cis 'CIS 5.1' --nist 'IA-2' --mitre 'T1087 (Account Discovery)' --iso27001 'A.8.2' \
            --nis2 'Art.21(2)(i)' --cis-macos 'CIS-macOS 2.11.4' --mscp 'N/A' \
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
            --cis 'CIS 4.8' --nist 'MP-7' --iso27001 'A.7.10' --nis2 'Art.21(2)(d)' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'Informational only.'
    else
        add_audit_result --category 'Removable Media & Peripheral Control' --control 'USB Restriction Profile Presence' \
            --status WARN --severity Medium \
            --current 'No configuration profile appears to manage USB restricted mode' \
            --recommended 'A configuration profile referencing USB restricted mode is installed' \
            --cis 'CIS 4.8' --nist 'MP-7' --iso27001 'A.7.10' --nis2 'Art.21(2)(d)' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'This is a best-effort text match against installed profile identifiers, not full profile-payload inspection — confirm manually via MDM console if USB device control is required by policy.'
    fi
}

check_thunderbolt_security_level() {
    if is_apple_silicon; then
        add_audit_result --category 'Removable Media & Peripheral Control' --control 'Thunderbolt Security Level' \
            --status INFO --severity Informational \
            --current 'Not applicable — Apple Silicon Mac (DMA protection is enforced independently of the legacy Thunderbolt security-level setting)' \
            --recommended 'N/A' \
            --cis 'CIS 4.8' --nist 'SC-7' --iso27001 'A.7.10' --nis2 'Art.21(2)(d)' --cis-macos 'N/A' --mscp 'N/A' \
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
            --recommended 'N/A' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'Informational only.'
        return
    fi

    if [[ "$line" == *"No Security"* || "$line" == *"Legacy"* ]]; then
        add_audit_result --category 'Removable Media & Peripheral Control' --control 'Thunderbolt Security Level' \
            --status FAIL --severity High --current "$line" \
            --recommended 'Security Level: User Authorization (or stricter)' \
            --cis 'CIS 4.8' --nist 'SC-7' --mitre 'T1200 (Hardware Additions)' --iso27001 'A.7.10' \
            --nis2 'Art.21(2)(d)' --nsa 'NSA/CISA DMA Protection Guidance' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'Set Thunderbolt security to "User Authorization" or stricter via the Thunderbolt pane (Intel Macs) or firmware boot security settings.'
    elif [[ "$line" == *"User Authorization"* ]]; then
        add_audit_result --category 'Removable Media & Peripheral Control' --control 'Thunderbolt Security Level' \
            --status PASS --severity High --current "$line" \
            --recommended 'Security Level: User Authorization (or stricter)' \
            --cis 'CIS 4.8' --nist 'SC-7' --mitre 'T1200 (Hardware Additions)' --iso27001 'A.7.10' \
            --nis2 'Art.21(2)(d)' --nsa 'NSA/CISA DMA Protection Guidance' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'No action required.'
    else
        # Fault isolation: an unrecognized security-level value must never
        # be silently reported identically to a verified-clean PASS above.
        add_audit_result --category 'Removable Media & Peripheral Control' --control 'Thunderbolt Security Level' \
            --status WARN --severity Low --current "Unrecognized security level: $line" \
            --recommended 'Security Level: User Authorization (or stricter)' \
            --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'Unable to classify the reported Thunderbolt security level; verify manually with "system_profiler SPThunderboltDataType".'
    fi
}

# ---- 30-wireless-network.zsh ----
#
# Domain 21: Wireless & Network Interface Security

check_wifi_current_network_security() {
    write_section_banner 'Wireless & Network Interface Security - Wi-Fi Current Network Security'
    run_prefetched wifi system_profiler SPAirPortDataType   # ~8s; prefetched in main()

    local block security_line
    block=$(print -r -- "$ROOT_CMD_OUTPUT" | awk '/Current Network Information:/{flag=1} flag{print}')
    security_line=$(print -r -- "$block" | grep 'Security:' | head -1)
    security_line="${security_line##*Security:}"
    security_line="${security_line## }"

    if [[ -z "$security_line" ]]; then
        add_audit_result --category 'Wireless & Network Interface Security' --control 'Wi-Fi Current Network Security' \
            --status INFO --severity Informational --current 'Not currently associated with a Wi-Fi network' \
            --recommended 'N/A' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'Informational only.'
    elif [[ "$security_line" == *"WEP"* || "$security_line" == *"None"* || "$security_line" == *"Open"* ]]; then
        add_audit_result --category 'Wireless & Network Interface Security' --control 'Wi-Fi Current Network Security' \
            --status WARN --severity Medium --current "$security_line" \
            --recommended 'WPA2 or WPA3' \
            --cis 'CIS 12.6' --nist 'AC-18' --mitre 'T1040 (Network Sniffing)' --iso27001 'A.8.20' \
            --nis2 'Art.21(2)(h)' --nsa 'NSA/CISA Wireless Security Guidance' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'Reconfigure or avoid this network — WEP and open networks provide no meaningful confidentiality.'
    elif [[ "$security_line" == *"WPA2"* || "$security_line" == *"WPA3"* ]]; then
        add_audit_result --category 'Wireless & Network Interface Security' --control 'Wi-Fi Current Network Security' \
            --status PASS --severity Medium --current "$security_line" \
            --recommended 'WPA2 or WPA3' \
            --cis 'CIS 12.6' --nist 'AC-18' --mitre 'T1040 (Network Sniffing)' --iso27001 'A.8.20' \
            --nis2 'Art.21(2)(h)' --nsa 'NSA/CISA Wireless Security Guidance' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'No action required.'
    else
        add_audit_result --category 'Wireless & Network Interface Security' --control 'Wi-Fi Current Network Security' \
            --status WARN --severity Low --current "Unrecognized security value: $security_line" \
            --recommended 'WPA2 or WPA3' \
            --cis-macos 'N/A' --mscp 'N/A' \
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
            --recommended 'N/A' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'Informational only.'
    else
        add_audit_result --category 'Wireless & Network Interface Security' --control 'Bluetooth Power State' \
            --status INFO --severity Informational --current 'Bluetooth powered off' \
            --recommended 'N/A' --cis-macos 'N/A' --mscp 'N/A' \
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
            --nis2 'Art.21(2)(h)' --cis-macos 'CIS-macOS 2.3.1.1' --mscp 'N/A' \
            --recommendation 'Set AirDrop to "Contacts Only" or "No One" via Control Center/System Settings unless open discovery is deliberately needed.'
    else
        add_audit_result --category 'Wireless & Network Interface Security' --control 'AirDrop Discovery Scope' \
            --status PASS --severity Medium --current "DiscoverableMode: $mode" \
            --recommended 'Contacts Only or No One' \
            --cis 'CIS 4.8' --nist 'AC-18' --mitre 'T1092 (Communication Through Removable Media)' --iso27001 'A.8.20' \
            --nis2 'Art.21(2)(h)' --cis-macos 'CIS-macOS 2.3.1.1' --mscp 'N/A' \
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
        --recommended 'N/A' --cis-macos 'N/A' --mscp 'N/A' \
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
    # Case-insensitive: the service entry may read "Keychain" or "KEYCHAIN_SYNC".
    if [[ "${accounts_dump:l}" == *keychain* ]]; then
        add_audit_result --category 'iCloud & Cloud Sync Surface' --control 'iCloud Keychain Sync Indicator' \
            --status INFO --severity Informational \
            --current 'An iCloud account with Keychain sync appears to be configured' \
            --recommended 'N/A' --cis-macos 'CIS-macOS 2.1.1.1' --mscp 'N/A' \
            --recommendation 'Informational only.'
    else
        add_audit_result --category 'iCloud & Cloud Sync Surface' --control 'iCloud Keychain Sync Indicator' \
            --status INFO --severity Informational \
            --current 'No iCloud Keychain sync indicator found (best-effort parse of an internal plist structure — verify manually in System Settings > Apple ID > iCloud if certainty is required)' \
            --recommended 'N/A' --cis-macos 'CIS-macOS 2.1.1.1' --mscp 'N/A' \
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
            --cis 'CIS 4.8' --nist 'PE-20' --iso27001 'A.7.10' --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 2.1.1.6' --mscp 'N/A' \
            --recommendation 'No action required — this is a theft-deterrence control.'
    elif [[ "$line" == *"Disabled"* ]]; then
        add_audit_result --category 'iCloud & Cloud Sync Surface' --control 'Activation Lock Status' \
            --status WARN --severity Medium --current "$line" \
            --recommended 'Activation Lock Status: Enabled' \
            --cis 'CIS 4.8' --nist 'PE-20' --iso27001 'A.7.10' --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 2.1.1.6' --mscp 'N/A' \
            --recommendation 'Consider enabling Find My Mac (System Settings > Apple ID > iCloud > Find My Mac) so Activation Lock engages.'
    else
        add_audit_result --category 'iCloud & Cloud Sync Surface' --control 'Activation Lock Status' \
            --status INFO --severity Informational --current 'Activation Lock Status not reported (older hardware without the feature)' \
            --recommended 'N/A' --cis-macos 'CIS-macOS 2.1.1.6' --mscp 'N/A' \
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
            --recommended 'N/A' --cis-macos 'CIS-macOS 2.1.1.2' --mscp 'N/A' \
            --recommendation 'Informational only.'
    else
        add_audit_result --category 'iCloud & Cloud Sync Surface' --control 'iCloud Drive Sync Indicator' \
            --status INFO --severity Informational --current 'iCloud Drive local sync folder absent' \
            --recommended 'N/A' --cis-macos 'CIS-macOS 2.1.1.2' --mscp 'N/A' \
            --recommendation 'Informational only.'
    fi
}

check_icloud_drive_sync_indicator() {
    if [[ -z "$CONSOLE_USER" ]]; then
        add_audit_result --category 'iCloud & Cloud Sync Surface' --control 'iCloud Drive Sync Indicator' \
            --status WARN --severity Low --current 'No console user detected' \
            --recommended 'N/A' --cis-macos 'CIS-macOS 2.1.1.2' --mscp 'N/A' \
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
            --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 6.3.1' --mscp 'N/A' \
            --recommendation 'Disable "Open safe files after downloading" in Safari > Settings > General — auto-opening downloaded archives/disk images is a long-standing abuse vector.'
    else
        add_audit_result --category 'Browser & Application Hardening' --control 'Safari Auto-Open Safe Downloads' \
            --status PASS --severity Medium --current "AutoOpenSafeDownloads=$auto_open" \
            --recommended 'AutoOpenSafeDownloads=0' \
            --cis 'CIS 9.2' --nist 'CM-7' --mitre 'T1204.002 (Malicious File)' --iso27001 'A.8.19' \
            --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 6.3.1' --mscp 'N/A' \
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
            --recommended 'N/A' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'Informational only.'
    else
        add_audit_result --category 'Browser & Application Hardening' --control 'Safari Developer Menu' \
            --status INFO --severity Informational --current 'Develop menu off' \
            --recommended 'N/A' --cis-macos 'N/A' --mscp 'N/A' \
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
            --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 6.3.3' --mscp 'N/A' \
            --recommendation 're-enable "Warn when visiting a fraudulent website" in Safari > Settings > Security.'
    else
        add_audit_result --category 'Browser & Application Hardening' --control 'Safari Fraudulent Site Warning' \
            --status PASS --severity Medium --current "WarnAboutFraudulentWebsites=$warn_setting" \
            --recommended 'WarnAboutFraudulentWebsites=1' \
            --cis 'CIS 9.2' --nist 'SC-7' --mitre 'T1566 (Phishing)' --iso27001 'A.8.23' \
            --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 6.3.3' --mscp 'N/A' \
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

# ---- 32b-browser-extensions.zsh ----
#
# Domain 23 (continued): Browser & Application Hardening - browser
# extensions. Chromium browsers (Chrome, Edge, Brave, Vivaldi, Arc,
# Chromium) and Firefox, in every local user's profiles, plus Safari web
# extensions. A 2026 campaign of 108 malicious Chrome extensions hit
# 20,000+ enterprise users; extensions are a common credential- and
# session-theft path that no other check sees.
#
# Manifests and preference files are JSON; they are parsed with
# JavaScript through osascript (JXA), so there is still no dependency
# beyond what macOS ships. Extension settings come from both
# "Preferences" and "Secure Preferences" — the only place unpacked
# (developer-mode) and policy-installed extensions are recorded.

typeset -g BROWSER_EXT_JXA
read -r -d '' BROWSER_EXT_JXA <<'JXA'
ObjC.import('Foundation');
function readJSON(p) {
    var s = $.NSString.stringWithContentsOfFileEncodingError(p, $.NSUTF8StringEncoding, null);
    if (s.isNil()) return null;
    try { return JSON.parse(ObjC.unwrap(s)); } catch (e) { return null; }
}
function listDir(p) {
    var c = ObjC.deepUnwrap($.NSFileManager.defaultManager.contentsOfDirectoryAtPathError(p, null)) || [];
    return c.filter(function (x) { return x[0] !== '.'; }).sort();
}
function localized(dir, m, s) {
    var r = /^__MSG_(.+)__$/.exec(s || '');
    if (!r || !dir) return s || '';
    var j = readJSON(dir + '/_locales/' + (m.default_locale || 'en') + '/messages.json') || readJSON(dir + '/_locales/en/messages.json');
    if (!j) return s;
    var k = Object.keys(j).filter(function (x) { return x.toLowerCase() === r[1].toLowerCase(); })[0];
    return k ? j[k].message : s;
}
function clean(v) { return String(v == null ? '' : v).replace(/[\t\n\r\x1f]/g, ' '); }
function chromium(prof) {
    var settings = {}, out = [];
    ['Preferences', 'Secure Preferences'].forEach(function (f) {
        var j = readJSON(prof + '/' + f), s = j && j.extensions && j.extensions.settings;
        if (s) for (var id in s) settings[id] = Object.assign(settings[id] || {}, s[id]);
    });
    listDir(prof + '/Extensions').forEach(function (id) { if (!settings[id]) settings[id] = {}; });
    for (var id in settings) {
        var st = settings[id], loc = st.location, dir = null, m = null;
        if (loc === 5 || loc === 10) continue;                       // built-in components
        if (st.path) dir = st.path[0] === '/' ? st.path : prof + '/Extensions/' + st.path;
        else { var v = listDir(prof + '/Extensions/' + id); if (v.length) dir = prof + '/Extensions/' + id + '/' + v[v.length - 1]; }
        if (dir) m = readJSON(dir + '/manifest.json');
        if (!m) m = st.manifest || null;
        if (!m || m.theme) continue;
        var perms = (m.permissions || []).filter(function (p) { return typeof p === 'string'; });
        var hosts = (m.host_permissions || []).concat(perms.filter(function (p) { return p.indexOf('://') >= 0 || p === '<all_urls>'; }));
        (m.content_scripts || []).forEach(function (cs) { hosts = hosts.concat(cs.matches || []); });
        var dr = st.disable_reasons, disabled = st.state === 0 || (Array.isArray(dr) ? dr.length > 0 : !!dr);
        out.push([id, localized(dir, m, m.name), m.version, loc == null ? '' : loc, m.update_url || '', disabled ? 0 : 1, '',
            perms.filter(function (p) { return p.indexOf('://') < 0 && p !== '<all_urls>'; }).join(','),
            hosts.filter(function (h, i) { return hosts.indexOf(h) === i; }).join(',')].map(clean).join('\x1f'));
    }
    return out.join('\n');
}
function firefox(prof) {
    var j = readJSON(prof + '/extensions.json'), out = [];
    ((j && j.addons) || []).forEach(function (a) {
        if (a.type !== 'extension' || /^app-(builtin|system-defaults|system-addons)$/.test(a.location)) return;
        var up = a.userPermissions || {};
        out.push([a.id, (a.defaultLocale && a.defaultLocale.name) || a.id, a.version, a.location, a.sourceURI || '', a.active ? 1 : 0,
            typeof a.signedState === 'number' ? String(a.signedState | 0) : '', (up.permissions || []).join(','), (up.origins || []).join(',')].map(clean).join('\x1f'));
    });
    return out.join('\n');
}
function run(argv) { return argv[0] === 'firefox' ? firefox(argv[1]) : chromium(argv[1]); }
JXA

# Chromium-family user-data roots, relative to a home directory.
typeset -ga CHROMIUM_ROOTS
CHROMIUM_ROOTS=(
    'Google Chrome|Library/Application Support/Google/Chrome'
    'Microsoft Edge|Library/Application Support/Microsoft Edge'
    'Brave|Library/Application Support/BraveSoftware/Brave-Browser'
    'Vivaldi|Library/Application Support/Vivaldi'
    'Arc|Library/Application Support/Arc/User Data'
    'Chromium|Library/Application Support/Chromium'
)

# Store update endpoints (host + path, matched exactly). Anything else, or
# none, means not installed from a store.
typeset -ga EXTENSION_STORE_URLS
EXTENSION_STORE_URLS=('clients2.google.com/service/update2/crx' 'edge.microsoft.com/extensionwebstorebase/v1/crx'
    'update.googleapis.com/service/update2')

# Returns 0 when an update URL is exactly a store endpoint. Parsed, not
# substring-matched: "https://evil.example/clients2.google.com/service/
# update2/crx" must not pass as store-hosted (an extension can set its own
# update_url). https only; userinfo, ports, queries and fragments rejected.
_is_store_update_url() {
    local url="$1" rest="" host="" path="" store=""
    [[ "$url" == https://* ]] || return 1
    rest="${url#https://}"
    [[ "$rest" == *[@?#\\]* ]] && return 1
    host="${${rest%%/*}:l}"; host="${host%.}"
    [[ "$host" == *:* ]] && return 1
    path="${rest#*/}"; [[ "$rest" == */* ]] || path=""
    path="${path%/}"
    for store in "${EXTENSION_STORE_URLS[@]}"; do
        [[ "$host/$path" == "$store" ]] && return 0
    done
    return 1
}

# Combined with every-site access these let an extension steal sessions,
# reroute or rewrite traffic, or reach outside the browser. Plain
# script injection / webRequest is common to ordinary ad blockers and
# spell checkers, so it is shown in the inventory but not flagged
# (measured live: flagging it marked 10 of 12 enabled extensions).
typeset -ga EXTENSION_SENSITIVE_PERMS
EXTENSION_SENSITIVE_PERMS=(cookies proxy nativeMessaging management webRequestBlocking)

# One line per extension: "browser|profile|user|" then id, name, version,
# location, update URL (Firefox: sourceURI), enabled, signedState, perms
# and hosts joined by \x1f. Not tabs: tab is IFS whitespace, so `read`
# would collapse empty fields and shift every later one.
_browser_extension_records() {
    local entry="" user="" home="" root="" browser="" rel="" prof="" line=""
    for entry in "${(@f)$(_local_user_homes)}"; do
        [[ -z "$entry" ]] && continue
        user="${entry%%$'\t'*}"; home="${entry#*$'\t'}"
        for root in "${CHROMIUM_ROOTS[@]}"; do
            browser="${root%%|*}"; rel="${root#*|}"
            for prof in "$home/$rel"/(Default|Profile*)(N/); do
                for line in "${(@f)$(osascript -l JavaScript -e "$BROWSER_EXT_JXA" chromium "$prof" 2>/dev/null)}"; do
                    [[ -n "$line" ]] && print -r -- "$browser|${prof:t}|$user|$line"
                done
            done
        done
        for prof in "$home/Library/Application Support/Firefox/Profiles"/*(N/); do
            for line in "${(@f)$(osascript -l JavaScript -e "$BROWSER_EXT_JXA" firefox "$prof" 2>/dev/null)}"; do
                [[ -n "$line" ]] && print -r -- "Firefox|${prof:t}|$user|$line"
            done
        done
    done
}

# Prints the risk reasons for one record (empty = nothing to flag).
_extension_risk_reasons() {
    local browser="$1" location="$2" update="$3" signed="$4" perms="$5" hosts="$6"
    local -a reasons sensitive
    local p="" url="" from_store=0 broad=0
    if [[ "$browser" == Firefox ]]; then
        [[ "$location" != app-profile ]] && reasons+=("sideloaded or temporary (location $location)")
        # signedState comes from a file the user controls. Never put it in an
        # arithmetic context: zsh evaluates arithmetic (including command
        # substitution in subscripts), which would run user input as root.
        # Validate the shape, then compare as strings.
        if [[ "$signed" == (-|)<-> ]] && [[ "$signed" == -* || "$signed" == 0 ]]; then
            reasons+=("unsigned (signedState $signed)")
        fi
    else
        _is_store_update_url "$update" && from_store=1
        case "$location" in
            4) reasons+=("unpacked (developer mode, not from a store)") ;;
            # Pre-installed through an external-extensions file. Store-hosted
            # ones (e.g. Chrome's bundled Google Docs Offline) are normal.
            2|6) (( from_store )) || reasons+=("sideloaded by an external extensions file, not store-hosted") ;;
            7|9) ;;   # force-installed by policy: listed in the inventory, not a risk by itself
            *) (( from_store )) || reasons+=("not from a browser store${update:+ (update URL $update)}") ;;
        esac
    fi
    [[ ",$perms," == *",debugger,"* ]] && reasons+=("debugger permission (full control of every tab)")
    [[ ",$hosts," == *"<all_urls>"* || ",$hosts," == *",*://*/"* || ",$hosts," == *",http://*/"* || ",$hosts," == *",https://*/"* ]] && broad=1
    if (( broad )); then
        for p in "${EXTENSION_SENSITIVE_PERMS[@]}"; do [[ ",$perms," == *",$p,"* ]] && sensitive+=("$p"); done
        (( ${#sensitive[@]} )) && reasons+=("every site + ${(j:, :)sensitive}")
    fi
    print -r -- "${(j:; :)reasons}"
}

_extension_source_label() {
    local browser="$1" location="$2"
    if [[ "$browser" == Firefox ]]; then
        [[ "$location" == app-profile ]] && print -r -- 'user-installed' || print -r -- "$location"
        return
    fi
    case "$location" in
        4) print -r -- unpacked ;;
        2|6) print -r -- sideloaded ;;
        7|9) print -r -- 'policy' ;;
        *) print -r -- store ;;
    esac
}

check_browser_extensions_inventory() {
    write_section_banner 'Browser & Application Hardening - Browser Extensions'
    local rec="" browser="" prof="" user="" rest="" id="" name="" version="" location="" update="" enabled="" signed="" perms="" hosts=""
    local -a lines safari
    local enabled_count=0
    local -A profiles
    for rec in "${(@f)$(_browser_extension_records)}"; do
        [[ -z "$rec" ]] && continue
        IFS='|' read -r browser prof user rest <<< "$rec"
        IFS=$'\x1f' read -r id name version location update enabled signed perms hosts <<< "$rest"
        profiles[$browser/$prof/$user]=1
        [[ "$enabled" == 1 ]] && enabled_count=$((enabled_count + 1))
        lines+=("[$browser $prof, $user] $name ${version:+v$version} ($( [[ "$enabled" == 1 ]] && print on || print off), $(_extension_source_label "$browser" "$location"))")
    done
    if [[ -n "$CONSOLE_USER" ]]; then
        run_as_user pluginkit -mA -p com.apple.Safari.web-extension
        [[ $RUN_AS_USER_STATUS -eq 0 ]] && safari=("${(@f)$(print -r -- "$RUN_AS_USER_OUTPUT" | awk 'NF {sub(/^[+!=-]? */, ""); print $1}')}")
        safari=(${safari:#})
        local s=""
        for s in "${safari[@]}"; do lines+=("[Safari, $CONSOLE_USER] $s (Safari web extension)"); done
    fi
    add_audit_result --category 'Browser & Application Hardening' --control 'Browser Extensions Inventory' \
        --status INFO --severity Informational \
        --current "$(( ${#lines[@]} )) extension(s) in ${#profiles} browser profile(s); $enabled_count enabled (Chromium/Firefox), ${#safari[@]} Safari" \
        --details "${(F)${(@o)lines}}" --recommended 'N/A' --cis 'CIS 9.4' --nist 'CM-7(5), CM-8' --iso27001 'A.8.19' \
        --cis-macos 'N/A' --mscp 'N/A' \
        --recommendation 'Informational baseline. Remove extensions nobody uses; enforce an allowlist with ExtensionInstallAllowlist / ExtensionSettings policies in managed environments.'
}

check_browser_extension_risk() {
    local rec="" browser="" prof="" user="" rest="" id="" name="" version="" location="" update="" enabled="" signed="" perms="" hosts="" reasons=""
    local -a flagged
    local total=0
    for rec in "${(@f)$(_browser_extension_records)}"; do
        [[ -z "$rec" ]] && continue
        IFS='|' read -r browser prof user rest <<< "$rec"
        IFS=$'\x1f' read -r id name version location update enabled signed perms hosts <<< "$rest"
        [[ "$enabled" == 1 ]] || continue
        total=$((total + 1))
        reasons=$(_extension_risk_reasons "$browser" "$location" "$update" "$signed" "$perms" "$hosts")
        [[ -n "$reasons" ]] && flagged+=("[$browser $prof, $user] $name ($id): $reasons")
    done
    local -a fw
    fw=(--recommended 'Enabled extensions come from a store and hold only the access they need'
        --cis 'CIS 9.4' --nist 'CM-7(5), SI-4' --mitre 'T1176 (Browser Extensions)' --iso27001 'A.8.19'
        --nis2 'Art.21(2)(d)' --cis-macos 'N/A' --mscp 'N/A')
    if [[ ${#flagged[@]} -gt 0 ]]; then
        add_audit_result --category 'Browser & Application Hardening' --control 'Browser Extension Risk Review' \
            --status WARN --severity Medium --current "${#flagged[@]} of $total enabled extension(s) need review" \
            --details "${(F)${(@o)flagged}}" "${fw[@]}" \
            --recommendation 'Review each listed extension: remove unpacked, sideloaded and unknown-source extensions, and keep broad-access ones (every site plus cookies, web requests, proxy or native messaging) only when they are from a vendor you trust. Extensions auto-update, so an ownership change can turn a trusted one malicious.'
    else
        add_audit_result --category 'Browser & Application Hardening' --control 'Browser Extension Risk Review' \
            --status PASS --severity Medium --current "$total enabled extension(s), none flagged" "${fw[@]}" \
            --recommendation 'No action required.'
    fi
}

# ---- 33-ransomware-resilience.zsh ----
#
# Domain 24: Ransomware Resilience & Recovery

check_time_machine_configured_and_recent() {
    write_section_banner 'Ransomware Resilience & Recovery - Time Machine Configured & Recent'
    run_root tmutil destinationinfo
    # "No destinations configured" exits 0 (verified live); a non-zero exit
    # is a failed query and must not be reported as "no backup".
    if [[ $ROOT_CMD_STATUS -ne 0 && "$ROOT_CMD_OUTPUT" != *"No destinations configured"* ]]; then
        add_audit_result --category 'Ransomware Resilience & Recovery' --control 'Time Machine Configured & Recent' \
            --status WARN --severity Low --current "tmutil query failed: $ROOT_CMD_OUTPUT" \
            --recommended 'A Time Machine destination is configured, backed up within 7 days' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'Unable to query Time Machine; re-run with sudo (Full Disk Access may be required) or check System Settings > General > Time Machine.'
        return
    fi

    if [[ "$ROOT_CMD_OUTPUT" == *"No destinations configured"* ]]; then
        add_audit_result --category 'Ransomware Resilience & Recovery' --control 'Time Machine Configured & Recent' \
            --status FAIL --severity High --current 'No Time Machine destination configured' \
            --recommended 'A Time Machine destination is configured, backed up within 7 days' \
            --cis 'CIS 11.2' --nist 'CP-9' --mitre 'T1490 (Inhibit System Recovery)' --iso27001 'A.8.13' \
            --nis2 'Art.21(2)(c)' --nsa 'NSA/CISA Ransomware Resilience Guidance' --cis-macos 'N/A' --mscp 'N/A' \
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
            --nis2 'Art.21(2)(c)' --nsa 'NSA/CISA Ransomware Resilience Guidance' --cis-macos 'N/A' --mscp 'N/A' \
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
            --nis2 'Art.21(2)(c)' --nsa 'NSA/CISA Ransomware Resilience Guidance' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'No action required.'
    else
        add_audit_result --category 'Ransomware Resilience & Recovery' --control 'Time Machine Configured & Recent' \
            --status WARN --severity Medium --current "$days_since day(s) since last backup" \
            --recommended 'A Time Machine destination is configured, backed up within 7 days' \
            --cis 'CIS 11.2' --nist 'CP-9' --mitre 'T1490 (Inhibit System Recovery)' --iso27001 'A.8.13' \
            --nis2 'Art.21(2)(c)' --nsa 'NSA/CISA Ransomware Resilience Guidance' --cis-macos 'N/A' --mscp 'N/A' \
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
        --recommended 'N/A' --cis-macos 'N/A' --mscp 'N/A' \
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

    names=("${(@o)names}")   # stable, readable order (find returns directory order)
    local total=${#names[@]}
    local joined
    joined=$(printf '%s\n' "${names[@]}")

    # Always INFO: this is inventory, not a judgement. The full name list
    # lives in --details (hover tooltip) rather than inline — with up to
    # a few dozen apps, showing it inline would blow out the row.
    add_audit_result --category 'Third-Party Software & Package Inventory' --control 'Installed Applications Inventory' \
        --status INFO --severity Informational --current "$total application(s) installed" \
        --details "$joined" \
        --recommended 'N/A' --cis-macos 'CIS-macOS 3.6' --mscp 'N/A' \
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
            --recommended 'N/A' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'Informational only.'
        return
    fi

    run_root stat -f '%Lp' "$prefix"
    if [[ $ROOT_CMD_STATUS -ne 0 ]]; then
        add_audit_result --category 'Third-Party Software & Package Inventory' --control 'Homebrew Prefix Permissions' \
            --status WARN --severity Low --current "stat query failed: $ROOT_CMD_OUTPUT" \
            --recommended 'No group/other write bit' --cis-macos 'N/A' --mscp 'N/A' \
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
            --nis2 'Art.21(2)(d)' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation "sudo chmod -R go-w $prefix — a writable Homebrew prefix lets any local user hijack the next brew invocation or any binary on \$PATH under that prefix."
    else
        add_audit_result --category 'Third-Party Software & Package Inventory' --control 'Homebrew Prefix Permissions' \
            --status PASS --severity High --current "$prefix mode $mode" \
            --recommended 'No group/other write bit' \
            --cis 'CIS 2.7' --nist 'CM-7, AC-6' --mitre 'T1574.007 (PATH Interception)' --iso27001 'A.8.19' \
            --nis2 'Art.21(2)(d)' --cis-macos 'N/A' --mscp 'N/A' \
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
            --recommended 'N/A' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'Informational only.'
        return
    fi

    if [[ ! -d "$prefix/Cellar" ]]; then
        add_audit_result --category 'Third-Party Software & Package Inventory' --control 'Homebrew Package Inventory' \
            --status INFO --severity Informational \
            --current "0 Homebrew formula directory(ies) found under Cellar (best-effort count, not equivalent to 'brew list')" \
            --recommended 'N/A' --cis-macos 'N/A' --mscp 'N/A' \
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
        --recommended 'N/A' --cis-macos 'N/A' --mscp 'N/A' \
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
        --cis 'CIS 12.4' --nist 'CA-9' --iso27001 'A.8.20' --nis2 'Art.21(2)(d)' --cis-macos 'N/A' --mscp 'N/A' \
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
        --recommended 'N/A' --cis-macos 'N/A' --mscp 'N/A' \
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
            --nis2 'Art.21(2)(d)' --nsa 'NSA/CISA Boot Integrity Guidance' --cis-macos 'N/A' --mscp 'os_secure_boot_verify' \
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
                --nis2 'Art.21(2)(d)' --nsa 'NSA/CISA Boot Integrity Guidance' --cis-macos 'N/A' --mscp 'os_secure_boot_verify' \
                --recommendation 'No action required.'
            ;;
        Reduced)
            add_audit_result --category 'Kernel & Boot Security' --control 'Boot Security Policy' \
                --status WARN --severity Medium --current 'Security Mode: Reduced' --details "$ROOT_CMD_OUTPUT" \
                --recommended 'Full Security' \
                --cis 'CIS 10.5' --nist 'SI-7' --mitre 'T1542.001 (System Firmware)' --iso27001 'A.8.24' \
                --nis2 'Art.21(2)(d)' --nsa 'NSA/CISA Boot Integrity Guidance' --cis-macos 'N/A' --mscp 'os_secure_boot_verify' \
                --recommendation 'Consider Full Security unless a specific, documented need (e.g. running unsigned kexts) requires Reduced.'
            ;;
        Permissive)
            add_audit_result --category 'Kernel & Boot Security' --control 'Boot Security Policy' \
                --status FAIL --severity High --current 'Security Mode: Permissive' --details "$ROOT_CMD_OUTPUT" \
                --recommended 'Full Security' \
                --cis 'CIS 10.5' --nist 'SI-7' --mitre 'T1542.001 (System Firmware)' --iso27001 'A.8.24' \
                --nis2 'Art.21(2)(d)' --nsa 'NSA/CISA Boot Integrity Guidance' --cis-macos 'N/A' --mscp 'os_secure_boot_verify' \
                --recommendation 'This disables nearly all boot-chain integrity verification; restore via Startup Security Utility in Recovery unless deliberately required for development.'
            ;;
        *)
            add_audit_result --category 'Kernel & Boot Security' --control 'Boot Security Policy' \
                --status WARN --severity Low --current 'Query failed or unrecognized output' --details "$ROOT_CMD_OUTPUT" \
                --recommended 'Full Security' \
                --cis-macos 'N/A' --mscp 'os_secure_boot_verify' \
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
            --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 5.1.4' --mscp 'os_sip_enable' \
            --recommendation 'No action required.'
    elif [[ "$ROOT_CMD_OUTPUT" == *"disabled"* ]]; then
        add_audit_result --category 'Kernel & Boot Security' --control 'Authenticated Root Status' \
            --status FAIL --severity High --current "$ROOT_CMD_OUTPUT" \
            --recommended 'Authenticated Root status: enabled' \
            --cis 'CIS 10.5' --nist 'SI-7' --mitre 'T1542.001 (System Firmware)' --iso27001 'A.8.24' \
            --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 5.1.4' --mscp 'os_sip_enable' \
            --recommendation 'Re-enable via "csrutil authenticated-root enable" from Recovery — this protects the integrity of the signed system volume against offline tampering.'
    else
        add_audit_result --category 'Kernel & Boot Security' --control 'Authenticated Root Status' \
            --status WARN --severity Low --current "Query failed or unrecognized output: $ROOT_CMD_OUTPUT" \
            --recommended 'Authenticated Root status: enabled' \
            --cis-macos 'CIS-macOS 5.1.4' --mscp 'os_sip_enable' \
            --recommendation 'Unable to determine authenticated root status; verify manually with "csrutil authenticated-root status".'
    fi
}

check_nvram_boot_args() {
    run_root nvram boot-args

    local -a parts
    parts=(${=ROOT_CMD_OUTPUT})
    local value="${(j: :)parts[2,-1]}"

    # Unset boot-args is "Error getting variable" with a non-zero exit;
    # any other failure is a failed query, not a verified "none set".
    if [[ $ROOT_CMD_STATUS -ne 0 && "$ROOT_CMD_OUTPUT" != *"Error getting variable"* ]]; then
        add_audit_result --category 'Kernel & Boot Security' --control 'NVRAM Boot-Args' \
            --status WARN --severity Low --current "nvram query failed: $ROOT_CMD_OUTPUT" \
            --recommended 'No boot-args set' --cis-macos 'CIS-macOS 5.1.3' --mscp 'os_mobile_file_integrity_enable' \
            --recommendation 'Unable to read NVRAM boot-args; verify manually with "nvram boot-args".'
    elif [[ $ROOT_CMD_STATUS -ne 0 || -z "$value" ]]; then
        add_audit_result --category 'Kernel & Boot Security' --control 'NVRAM Boot-Args' \
            --status PASS --severity Low --current 'No boot-args set' \
            --recommended 'No boot-args set' \
            --cis 'CIS 10.5' --nist 'SI-7, CM-6' --mitre 'T1542.001 (System Firmware)' --iso27001 'A.8.24' \
            --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 5.1.3' --mscp 'N/A' \
            --recommendation 'No action required.'
    elif [[ "$value" == *"amfi_get_out_of_my_way=1"* || "$value" == *"cs_enforcement_disable=1"* || "$value" == *"-arm64e_preview_abi"* ]]; then
        add_audit_result --category 'Kernel & Boot Security' --control 'NVRAM Boot-Args' \
            --status FAIL --severity Critical --current "$value" \
            --recommended 'No boot-args set' \
            --cis 'CIS 10.5' --nist 'SI-7, CM-6' --mitre 'T1542.001 (System Firmware)' --iso27001 'A.8.24' \
            --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 5.1.3' --mscp 'N/A' \
            --recommendation 'Clear the dangerous boot-arg immediately — these disable code-signing/AMFI enforcement at the kernel level; treat as a possible active-compromise indicator.'
    else
        add_audit_result --category 'Kernel & Boot Security' --control 'NVRAM Boot-Args' \
            --status WARN --severity Low --current "$value" \
            --recommended 'No boot-args set' \
            --cis 'CIS 10.5' --nist 'SI-7, CM-6' --mitre 'T1542.001 (System Firmware)' --iso27001 'A.8.24' \
            --nis2 'Art.21(2)(d)' --cis-macos 'CIS-macOS 5.1.3' --mscp 'N/A' \
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
            --nis2 'Art.21(2)(d)' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'No action required.'
    else
        local joined
        joined=$(printf '%s\n' "${thirdparty[@]}")
        add_audit_result --category 'Kernel & Boot Security' --control 'Third-Party Kernel Extension Inventory' \
            --status WARN --severity High --current "${#thirdparty[@]} non-Apple kext(s) loaded" \
            --details "$joined" \
            --recommended 'No non-Apple kernel extensions loaded' \
            --cis 'CIS 2.5' --nist 'CM-7, SI-7' --mitre 'T1547.006 (Kernel Modules and Extensions)' --iso27001 'A.8.19' \
            --nis2 'Art.21(2)(d)' --cis-macos 'N/A' --mscp 'N/A' \
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
            --recommended 'N/A' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'Informational only.'
    else
        add_audit_result --category 'Virtualization & Container Escape Surface' --control 'Docker Desktop Presence' \
            --status INFO --severity Informational --current 'Docker Desktop is not running' \
            --recommended 'N/A' --cis-macos 'N/A' --mscp 'N/A' \
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
        --recommended 'N/A' --cis-macos 'N/A' --mscp 'N/A' \
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
            --cis 'CIS 3.11' --nist 'SI-4' --iso27001 'A.8.12' --nis2 'Art.21(2)(h)' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'Be aware screenshots may contain sensitive on-screen data and could sync to iCloud from this location; change the save location in Screenshot app preferences if that'"'"'s undesired.'
    else
        add_audit_result --category 'Data Loss Prevention & Sensitive Data' --control 'Screenshot Save Location Cloud Exposure' \
            --status PASS --severity Low --current "$location" \
            --recommended 'A non-iCloud save location' \
            --cis 'CIS 3.11' --nist 'SI-4' --iso27001 'A.8.12' --nis2 'Art.21(2)(h)' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'No action required.'
    fi
}

# Handoff / Universal Clipboard: enforced off by a Restrictions profile
# (allowActivityContinuation=false, mSCP os_handoff_disable), or turned
# off by the user (ByHost com.apple.coreservices.useractivityd, both
# ActivityAdvertisingAllowed and ActivityReceivingAllowed false). Enabled
# is the macOS default, so it is reported as INFO rather than a failure.
check_handoff_universal_clipboard() {
    local profile="" advertising="" receiving=""
    profile=$(managed_pref_read com.apple.applicationaccess allowActivityContinuation)
    if [[ -n "$CONSOLE_USER" ]]; then
        run_as_user defaults -currentHost read com.apple.coreservices.useractivityd ActivityAdvertisingAllowed
        [[ $RUN_AS_USER_STATUS -eq 0 ]] && advertising="$RUN_AS_USER_OUTPUT"
        run_as_user defaults -currentHost read com.apple.coreservices.useractivityd ActivityReceivingAllowed
        [[ $RUN_AS_USER_STATUS -eq 0 ]] && receiving="$RUN_AS_USER_OUTPUT"
    fi
    local -a fw
    fw=(--recommended 'Handoff disabled where clipboard and app state must not cross devices'
        --cis 'CIS 4.8' --nist 'AC-20, SC-7' --mitre 'T1115 (Clipboard Data)' --iso27001 'A.5.14'
        --nis2 'Art.21(2)(d)' --cis-macos 'N/A' --mscp 'os_handoff_disable')
    if [[ "$profile" == 0 ]]; then
        add_audit_result --category 'Data Loss Prevention & Sensitive Data' --control 'Handoff / Universal Clipboard' \
            --status PASS --severity Low --current 'Disabled by configuration profile (allowActivityContinuation=false)' "${fw[@]}" \
            --recommendation 'No action required.'
    elif [[ "$advertising" == 0 && "$receiving" == 0 ]]; then
        add_audit_result --category 'Data Loss Prevention & Sensitive Data' --control 'Handoff / Universal Clipboard' \
            --status PASS --severity Low --current "Turned off by ${CONSOLE_USER} (not enforced by a profile)" "${fw[@]}" \
            --recommendation 'No action required; enforce with a Restrictions profile (allowActivityContinuation=false) to keep it off.'
    else
        add_audit_result --category 'Data Loss Prevention & Sensitive Data' --control 'Handoff / Universal Clipboard' \
            --status INFO --severity Informational \
            --current "Handoff enabled (macOS default${profile:+; profile allowActivityContinuation=$profile})" "${fw[@]}" \
            --recommendation 'Clipboard contents and app activity sync to every device signed in to the same Apple Account. Where that is unacceptable, deploy a Restrictions profile with allowActivityContinuation=false.'
        [[ "$profile" != 1 ]] && record_profile_fix com.apple.applicationaccess allowActivityContinuation 0
    fi
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
        --recommended 'N/A' --cis-macos 'N/A' --mscp 'N/A' \
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
        --recommended 'N/A' --cis-macos 'N/A' --mscp 'N/A' \
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
            --recommended '>=10% free' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'Free up disk space — low free space can block macOS updates and Time Machine snapshots.'
    else
        add_audit_result --category 'System Inventory & Asset Information' --control 'Disk Space Utilization' \
            --status PASS --severity Low --current "$capacity used ($free_pct% free)" \
            --recommended '>=10% free' --cis-macos 'N/A' --mscp 'N/A' \
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

    names=("${(@o)names}")   # stable, readable order (find returns directory order)
    local joined
    joined=$(printf '%s\n' "${names[@]}")

    # Always INFO: reused here only as a count for the System Overview
    # panel, not re-judged.
    add_audit_result --category 'System Inventory & Asset Information' --control 'Installed Application Count' \
        --status INFO --severity Informational --current "${#names[@]} application(s)" \
        --details "$joined" \
        --recommended 'N/A' --cis-macos 'N/A' --mscp 'N/A' \
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
            --recommended 'N/A' --cis-macos 'N/A' --mscp 'N/A' \
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
        --recommended 'N/A' --cis-macos 'N/A' --mscp 'N/A' \
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

# ---- 42-attack-paths.zsh ----
#
# Attack paths and privilege escalation (macOS): settings and files an attacker with a
# foothold uses to gain root, bypass TCC/Gatekeeper, or keep access. Each check reports into
# the existing domain it belongs to; none re-evaluates a setting another check already scores.
#
# Values read from files or preferences are never used in arithmetic (zsh evaluates command
# substitution inside arithmetic subscripts): file modes are validated as digits and then
# matched as strings.

# Prints "owner mode" (mode in octal, e.g. "root 644") for a path, or nothing.
_owner_mode() {
    stat -f '%Su %Lp' "$1" 2>/dev/null
}

# True when a path is writable by someone other than root: not owned by root, group/other
# writable, or granted write through an extended ACL. Missing paths are not writable.
_writable_by_non_root() {
    local om="" owner="" mode=""
    om=$(_owner_mode "$1") || return 1
    [[ -z "$om" ]] && return 1
    owner="${om%% *}"; mode="${om##* }"
    [[ "$owner" != root ]] && return 0
    _mode_group_or_other_writable "$mode" && return 0
    _acl_write_grantees "$1" root >/dev/null
}

# ---------------------------------------------------------------- TCC

# Apps that run whatever script or command they are given: a TCC grant to one of them is a
# grant to every script started from it.
typeset -ga TCC_SCRIPT_HOSTS
TCC_SCRIPT_HOSTS=(
    com.apple.Terminal com.googlecode.iterm2 dev.warp.Warp-Stable com.github.wez.wezterm net.kovidgoyal.kitty
    io.alacritty com.mitchellh.ghostty co.zeit.hyper com.microsoft.VSCode com.apple.ScriptEditor2
    /bin/bash /bin/zsh /bin/sh /usr/bin/osascript /usr/bin/python3 /usr/bin/perl /usr/bin/ruby
)
typeset -gA TCC_SERVICE_LABELS
TCC_SERVICE_LABELS=(
    kTCCServiceSystemPolicyAllFiles 'Full Disk Access' kTCCServiceAccessibility 'Accessibility'
    kTCCServiceScreenCapture 'Screen Recording' kTCCServicePostEvent 'Input Monitoring (post events)'
    kTCCServiceListenEvent 'Input Monitoring'
)

check_tcc_grants_to_script_hosts() {
    local db="${1:-/Library/Application Support/com.apple.TCC/TCC.db}"
    local -a fw
    fw=(--recommended 'Powerful TCC grants go to code-signed apps, pinned by a code requirement, not to script hosts'
        --cis 'CIS 3.3, 6.1' --nist 'AC-6, CM-7' --mitre 'T1548 (Abuse Elevation Control Mechanism), T1059 (Command and Scripting Interpreter)'
        --iso27001 'A.8.2' --nis2 'Art.21(2)(i)' --cis-macos 'N/A' --mscp 'N/A')
    run_root sqlite3 -separator $'\x1f' "$db" "SELECT service, client, client_type, csreq IS NULL FROM access WHERE auth_value=2 AND service IN ('kTCCServiceSystemPolicyAllFiles','kTCCServiceAccessibility','kTCCServiceScreenCapture','kTCCServicePostEvent','kTCCServiceListenEvent');"
    if [[ "$ROOT_CMD_OUTPUT" == *"authorization denied"* || $ROOT_CMD_STATUS -ne 0 ]]; then
        add_audit_result --category 'TCC & Privacy Controls' --control 'TCC Grants to Script Hosts & Unpinned Clients' \
            --status INFO --severity Informational --current 'TCC database not readable from this process' "${fw[@]}" \
            --recommendation 'Grant Full Disk Access to the terminal running this audit to evaluate which apps hold Full Disk Access, Accessibility, Screen Recording and Input Monitoring.'
        return
    fi
    local line="" service="" client="" ctype="" nocsreq="" label=""
    local -a pinned_risk hosts
    for line in "${(@f)ROOT_CMD_OUTPUT}"; do
        [[ -z "$line" ]] && continue
        IFS=$'\x1f' read -r service client ctype nocsreq <<< "$line"
        label="${TCC_SERVICE_LABELS[$service]:-$service}"
        if [[ "$nocsreq" == 1 ]]; then
            pinned_risk+=("$client ($label): no code requirement, so whatever sits at that path or bundle ID inherits the grant")
        elif [[ "$ctype" == 1 ]] && _writable_by_non_root "$client"; then
            pinned_risk+=("$client ($label): binary is writable by a non-root user")
        fi
        if (( ${TCC_SCRIPT_HOSTS[(Ie)$client]} )) || [[ "$ctype" == 1 && "$client" == (/opt/homebrew/*|/usr/local/*) ]]; then
            hosts+=("$client ($label): every script or command started from it inherits $label")
        fi
    done
    if (( ${#pinned_risk[@]} )); then
        add_audit_result --category 'TCC & Privacy Controls' --control 'TCC Grants to Script Hosts & Unpinned Clients' \
            --status WARN --severity Medium --current "${#pinned_risk[@]} grant(s) not pinned to a code signature${hosts:+, ${#hosts[@]} to script hosts}" \
            --details "${(F)pinned_risk}${hosts:+$NL${(F)hosts}}" "${fw[@]}" \
            --recommendation 'Remove the listed grants in System Settings > Privacy & Security and re-grant only to the signed app that needs it. A grant without a code requirement, or to a binary a user can replace, can be taken over by planting a different program at that path.'
    elif (( ${#hosts[@]} )); then
        add_audit_result --category 'TCC & Privacy Controls' --control 'TCC Grants to Script Hosts & Unpinned Clients' \
            --status WARN --severity Low --current "${#hosts[@]} powerful grant(s) to terminals or interpreters" \
            --details "${(F)hosts}" "${fw[@]}" \
            --recommendation 'A terminal or interpreter with Full Disk Access or Accessibility passes that access to every script, package install hook and tool it runs. Keep such grants to admin workstations that need them, and remove them where they were only granted once for a task.'
    else
        add_audit_result --category 'TCC & Privacy Controls' --control 'TCC Grants to Script Hosts & Unpinned Clients' \
            --status PASS --severity Medium --current 'No powerful grants to script hosts or unpinned clients' "${fw[@]}" \
            --recommendation 'No action required.'
    fi
}

# ---------------------------------------------------------------- sudo

# Environment variables that make the program sudo runs load attacker code.
typeset -ga SUDO_DANGEROUS_ENV
SUDO_DANGEROUS_ENV=(DYLD_ LD_PRELOAD LD_LIBRARY_PATH PYTHONPATH PYTHONSTARTUP PYTHONHOME PERL5LIB PERL5OPT
    RUBYLIB RUBYOPT NODE_OPTIONS NODE_PATH BASH_ENV ENV SHELLOPTS PS4 GIT_EXEC_PATH)

check_sudo_environment_and_dropins() {
    local -a findings files unreadable
    local f="" line="" trimmed="" om="" v=""
    run_root find /etc/sudoers.d -maxdepth 1 -type f
    files=(/etc/sudoers "${(@f)ROOT_CMD_OUTPUT}"); files=(${files:#})
    for f in "${files[@]}"; do
        [[ "$f" == /etc/sudoers* ]] || continue
        om=$(_owner_mode "$f")
        if [[ -n "$om" ]] && { [[ "${om%% *}" != root ]] || _mode_group_or_other_writable "${om##* }"; }; then
            findings+=("$f is writable by a non-root user ($om): anyone who can edit it can grant themselves root")
        fi
        run_root cat "$f"
        if [[ $ROOT_CMD_STATUS -ne 0 ]]; then unreadable+=("$f"); continue; fi
        for line in "${(@f)ROOT_CMD_OUTPUT}"; do
            trimmed="${line#"${line%%[![:space:]]*}"}"
            [[ -z "$trimmed" || "$trimmed" == \#* ]] && continue
            [[ "$trimmed" == *'!env_reset'* ]] && findings+=("$f: env_reset disabled, the caller's whole environment reaches root")
            [[ "$trimmed" == Defaults*setenv* && "$trimmed" != *'!setenv'* ]] && findings+=("$f: setenv lets callers pass any variable to root")
            [[ "$trimmed" == *SETENV:* ]] && findings+=("$f: SETENV tag lets the caller pass any variable: $trimmed")
            if [[ "$trimmed" == *env_keep* ]]; then
                for v in "${SUDO_DANGEROUS_ENV[@]}"; do
                    [[ "$trimmed" == *"$v"* ]] && { findings+=("$f: env_keep keeps $v (makes the root program load attacker code)"); break; }
                done
            fi
        done
    done
    local -a fw
    fw=(--recommended 'sudo resets the environment, keeps no loader/interpreter variables, and only root can edit sudoers files'
        --cis 'CIS 5.4' --nist 'AC-6, CM-6' --mitre 'T1548.003 (Sudo and Sudo Caching), T1574.006 (Dynamic Linker Hijacking)'
        --iso27001 'A.8.2' --nis2 'Art.21(2)(i)' --cis-macos 'N/A' --mscp 'N/A')
    if (( ${#unreadable[@]} )) && (( ${#findings[@]} == 0 )); then
        add_audit_result --category 'Identity, Accounts & Privilege Management' --control 'Sudo Environment & Drop-in Permissions' \
            --status WARN --severity Low --current "Could not read ${#unreadable[@]} sudoers file(s)" --details "${(F)unreadable}" "${fw[@]}" \
            --recommendation 'Run the audit with sudo so the sudoers files can be read.'
    elif (( ${#findings[@]} )); then
        add_audit_result --category 'Identity, Accounts & Privilege Management' --control 'Sudo Environment & Drop-in Permissions' \
            --status FAIL --severity High --current "${#findings[@]} issue(s) in sudoers" --details "${(F)findings}" "${fw[@]}" \
            --recommendation 'Edit with "sudo visudo" (or "sudo visudo -f /etc/sudoers.d/<file>"): keep env_reset on, remove loader/interpreter variables (DYLD_*, LD_*, PYTHONPATH, PERL5LIB, NODE_OPTIONS, BASH_ENV ...) from env_keep, drop SETENV/setenv, and make every sudoers file root:wheel 0440.'
    else
        add_audit_result --category 'Identity, Accounts & Privilege Management' --control 'Sudo Environment & Drop-in Permissions' \
            --status PASS --severity High --current "${#files[@]} sudoers file(s): environment reset, no dangerous variables kept, root-only" "${fw[@]}" \
            --recommendation 'No action required.'
    fi
}

# Programs that turn a "restricted" sudo rule into root anyway (GTFOBins "sudo" entries):
# they spawn a shell, run arbitrary code, or write any file. Matched on the basename.
typeset -ga SUDO_SHELL_ESCAPE_BINS SUDO_FILE_READ_BINS
SUDO_SHELL_ESCAPE_BINS=(vi vim nvim view vimdiff rvim ex ed nano pico emacs less more man most find awk gawk nawk mawk
    sed perl python python2 python3 ruby irb lua php node nodejs bash sh zsh ksh csh tcsh dash fish env tar zip
    rsync scp ssh sftp ftp git nmap tcpdump wget curl cp mv tee dd chmod chown install ln openssl socat nc ncat
    script expect xargs time timeout watch nice strace gdb lldb make docker pip pip3 npm gem brew osascript screen
    tmux crontab sqlite3 mysql psql su sudo login dtrace launchctl ditto)
SUDO_FILE_READ_BINS=(cat head tail base64 xxd hexdump strings od diff sort uniq grep egrep fgrep cut nl fold)

# Command lists of sudoers rules and Cmnd_Alias definitions, one command per line.
_sudoers_rule_commands() {
    local text="$1" line="" joined="" cmds="" c=""
    # Join backslash continuations first.
    text="${text//\\$'\n'/ }"
    for line in "${(@f)text}"; do
        line="${line#"${line%%[![:space:]]*}"}"
        [[ -z "$line" || "$line" == \#* || "$line" == Defaults* || "$line" == (User|Host|Runas)_Alias* ]] && continue
        [[ "$line" == *=* ]] || continue
        cmds="${line#*=}"
        [[ "$line" == Cmnd_Alias* ]] || cmds="${cmds#*\)}"    # drop "(runas)"
        for c in "${(@s:,:)cmds}"; do
            c="${c#"${c%%[![:space:]]*}"}"
            # Drop tags (NOPASSWD:, SETENV:, ...) but remember NOPASSWD.
            while [[ "$c" =~ '^[A-Z_]+:' ]]; do
                case "$c" in NOPASSWD:*) joined="NOPASSWD" ;; PASSWD:*) joined="" ;; esac
                c="${c#*:}"; c="${c#"${c%%[![:space:]]*}"}"
            done
            [[ -z "$c" || "$c" == '!'* || "$c" == ALL ]] && continue
            print -r -- "${joined:+NOPASSWD }$c"
        done
        joined=""
    done
}

check_sudo_rules_shell_escape() {
    local -a files unreadable escape readers wild
    local f="" entry="" cmd="" bin="" nopw=""
    run_root find /etc/sudoers.d -maxdepth 1 -type f
    files=(/etc/sudoers "${(@f)ROOT_CMD_OUTPUT}"); files=(${files:#})
    for f in "${files[@]}"; do
        [[ "$f" == /etc/sudoers* ]] || continue
        run_root cat "$f"
        if [[ $ROOT_CMD_STATUS -ne 0 ]]; then unreadable+=("$f"); continue; fi
        for entry in "${(@f)$(_sudoers_rule_commands "$ROOT_CMD_OUTPUT")}"; do
            [[ -z "$entry" ]] && continue
            nopw=""; [[ "$entry" == 'NOPASSWD '* ]] && { nopw=" (NOPASSWD)"; entry="${entry#NOPASSWD }"; }
            cmd="${entry%% *}"; bin="${cmd:t}"
            if (( ${SUDO_SHELL_ESCAPE_BINS[(Ie)$bin]} )); then
                escape+=("$f: $entry$nopw — $bin can start a root shell or write any file")
            elif (( ${SUDO_FILE_READ_BINS[(Ie)$bin]} )); then
                readers+=("$f: $entry$nopw — $bin can read any file as root")
            elif [[ "$entry" == *' '*'*'* ]]; then
                wild+=("$f: $entry$nopw — a wildcard in the arguments matches more than intended (e.g. ../ or extra options)")
            elif [[ "$cmd" == /* ]] && { _writable_by_non_root "$cmd" || _writable_by_non_root "${cmd:h}"; }; then
                escape+=("$f: $entry$nopw — the program or its folder is writable by a non-root user")
            fi
        done
    done
    local -a fw all
    fw=(--recommended 'sudo rules only allow programs that cannot run other code, without argument wildcards'
        --cis 'CIS 5.4' --nist 'AC-6' --mitre 'T1548.003 (Sudo and Sudo Caching)'
        --iso27001 'A.8.2' --nis2 'Art.21(2)(i)' --cis-macos 'N/A' --mscp 'N/A')
    all=("${escape[@]}" "${readers[@]}" "${wild[@]}")
    if (( ${#escape[@]} )); then
        add_audit_result --category 'Identity, Accounts & Privilege Management' --control 'Sudo Rules Allowing Shell Escapes' \
            --status FAIL --severity High --current "${#escape[@]} sudo rule(s) amount to full root" --details "${(F)all}" "${fw[@]}" \
            --recommendation 'A sudo rule for an editor, pager, interpreter, archiver or copier is a root shell (see gtfobins.github.io). Replace it with a root-owned wrapper script that does only the intended task, or remove it. Never allow programs in user-writable folders.'
    elif (( ${#readers[@]} || ${#wild[@]} )); then
        add_audit_result --category 'Identity, Accounts & Privilege Management' --control 'Sudo Rules Allowing Shell Escapes' \
            --status WARN --severity Medium --current "${#all[@]} sudo rule(s) broader than they look" --details "${(F)all}" "${fw[@]}" \
            --recommendation 'File readers let the user read any file as root (e.g. /etc/master.passwd-equivalents, keychains, SSH keys); wildcards match extra paths and options. Narrow each rule to exact arguments.'
    elif (( ${#unreadable[@]} )); then
        add_audit_result --category 'Identity, Accounts & Privilege Management' --control 'Sudo Rules Allowing Shell Escapes' \
            --status WARN --severity Low --current "Could not read ${#unreadable[@]} sudoers file(s)" --details "${(F)unreadable}" "${fw[@]}" \
            --recommendation 'Run the audit with sudo so the sudoers files can be read.'
    else
        add_audit_result --category 'Identity, Accounts & Privilege Management' --control 'Sudo Rules Allowing Shell Escapes' \
            --status PASS --severity High --current 'No sudo rule allows a shell-escape program, file reader or argument wildcard' "${fw[@]}" \
            --recommendation 'No action required.'
    fi
}

# ---------------------------------------------------------------- authorization database

# Rights and the rules they build on whose stock definitions always require an admin
# password. "allow" (or a rule that is allow, or authenticate-user false) removes that.
typeset -ga AUTHDB_RIGHTS
AUTHDB_RIGHTS=(system.privilege.admin system.preferences system.preferences.security system.preferences.accounts
    system.services.directory.configure authenticate-admin-nonshared authenticate-admin admin)

check_authorization_db_weakened_rights() {
    local right="" xml="" cls="" rule="" auth_user="" read_ok=0
    local -a weak
    for right in "${AUTHDB_RIGHTS[@]}"; do
        run_root security authorizationdb read "$right"
        [[ $ROOT_CMD_STATUS -eq 0 && "$ROOT_CMD_OUTPUT" == *'<plist'* ]] || continue
        read_ok=$((read_ok + 1))
        # run_root merges stderr, where security prints "YES (0)" after the plist.
        xml="<?xml${ROOT_CMD_OUTPUT#*<\?xml}"; xml="${xml%%</plist>*}</plist>"
        cls=$(print -r -- "$xml" | plutil -extract class raw -o - - 2>/dev/null)
        rule=$(print -r -- "$xml" | plutil -extract rule json -o - - 2>/dev/null)
        auth_user=$(print -r -- "$xml" | plutil -extract authenticate-user raw -o - - 2>/dev/null)
        if [[ "$cls" == allow ]]; then weak+=("$right: class allow (no authentication)")
        elif [[ "$rule" == *'"allow"'* ]]; then weak+=("$right: rule allow (no authentication)")
        elif [[ "$cls" == user && "$auth_user" == false ]]; then weak+=("$right: authenticate-user false (group membership alone is enough)")
        fi
    done
    local -a fw
    fw=(--recommended 'Admin rights in the authorization database require authentication (stock rules)'
        --cis 'CIS 5.4' --nist 'AC-3, AC-6' --mitre 'T1548 (Abuse Elevation Control Mechanism), T1556 (Modify Authentication Process)'
        --iso27001 'A.8.2' --nis2 'Art.21(2)(i)' --cis-macos 'N/A' --mscp 'N/A')
    if (( read_ok == 0 )); then
        add_audit_result --category 'Identity, Accounts & Privilege Management' --control 'Authorization Database Admin Rights' \
            --status WARN --severity Low --current 'Could not read the authorization database' "${fw[@]}" \
            --recommendation 'Verify manually: "security authorizationdb read system.privilege.admin" should use authenticate-admin-nonshared.'
    elif (( ${#weak[@]} )); then
        add_audit_result --category 'Identity, Accounts & Privilege Management' --control 'Authorization Database Admin Rights' \
            --status FAIL --severity High --current "${#weak[@]} admin right(s) no longer require authentication" --details "${(F)weak}" "${fw[@]}" \
            --recommendation 'Restore the stock definition, e.g. "sudo security authorizationdb write system.privilege.admin authenticate-admin-nonshared". A right set to allow lets any process perform that admin action without a password; it is a known persistence and escalation trick.'
    else
        add_audit_result --category 'Identity, Accounts & Privilege Management' --control 'Authorization Database Admin Rights' \
            --status PASS --severity High --current "$read_ok admin right(s) checked; all require authentication" "${fw[@]}" \
            --recommendation 'No action required.'
    fi
}

# ---------------------------------------------------------------- PAM

typeset -ga PAM_SENSITIVE_SERVICES
PAM_SENSITIVE_SERVICES=(sudo sudo_local su login authorization screensaver sshd passwd chkpasswd)

check_pam_configuration_integrity() {
    local dir="${1:-/etc/pam.d}" f="" line="" trimmed="" svc="" module="" control="" modpath="" i=0
    local -a words fails warns
    for f in "$dir"/*(N.); do
        svc="${f:t}"
        [[ "$svc" == *.template ]] && continue
        for line in "${(@f)$(<"$f")}"; do
            trimmed="${line#"${line%%[![:space:]]*}"}"
            [[ -z "$trimmed" || "$trimmed" == \#* ]] && continue
            words=(${=trimmed})
            (( ${#words[@]} >= 3 )) || continue
            control="${words[2]}"; module="${words[3]}"
            if [[ "$control" == \[* ]]; then   # [value=action ...] spans several words
                i=2
                while (( i <= ${#words[@]} )) && [[ "${words[$i]}" != *\] ]]; do i=$((i + 1)); done
                module="${words[$((i + 1))]:-}"
            fi
            [[ -z "$module" ]] && continue
            # include/substack name another PAM service (checked as its own file), not a module.
            [[ "$control" == (include|substack) ]] && continue
            # Not "path": in zsh that name is tied to $PATH.
            if [[ "$module" == /* ]]; then modpath="$module"; else modpath="/usr/lib/pam/$module"; fi
            # "sufficient" (or a [success=...] control) pam_permit short-circuits the stack: any
            # password works. Stock macOS uses only "required" pam_permit (e.g. passwd auth),
            # which cannot bypass the real password module and is not flagged.
            if [[ "$module" == pam_permit.so* && "${words[1]}" == auth && "$control" == (sufficient|\[*) ]] &&
               [[ ${PAM_SENSITIVE_SERVICES[(Ie)$svc]} != 0 ]]; then
                fails+=("$svc: auth $control $module (accepts any password)")
            elif [[ "$modpath" != /usr/lib/pam/* ]]; then
                if _writable_by_non_root "$modpath" || _writable_by_non_root "${modpath:h}"; then
                    fails+=("$svc: $module is writable by a non-root user and loads into ${svc} as root")
                else
                    warns+=("$svc: $module (outside /usr/lib/pam)")
                fi
            elif [[ ! -e "$modpath" && ! -e "$modpath.2" ]]; then
                warns+=("$svc: $module not found in /usr/lib/pam")
            fi
        done
    done
    local -a fw
    fw=(--recommended 'PAM stacks use only Apple modules from /usr/lib/pam; no pam_permit in authentication'
        --cis 'CIS 5.4' --nist 'IA-2, SI-7' --mitre 'T1556.003 (Pluggable Authentication Modules)'
        --iso27001 'A.8.5' --nis2 'Art.21(2)(j)' --cis-macos 'N/A' --mscp 'N/A')
    if (( ${#fails[@]} )); then
        add_audit_result --category 'Identity, Accounts & Privilege Management' --control 'PAM Configuration Integrity' \
            --status FAIL --severity High --current "${#fails[@]} PAM entry(ies) bypass or expose authentication" \
            --details "${(F)fails}${warns:+$NL${(F)warns}}" "${fw[@]}" \
            --recommendation 'Remove pam_permit from authentication stacks, and make sure every third-party module and its folder is root-owned and not writable by users (a Homebrew-installed module such as pam_reattach under /opt/homebrew is user-writable: replacing it gives root on the next sudo).'
    elif (( ${#warns[@]} )); then
        add_audit_result --category 'Identity, Accounts & Privilege Management' --control 'PAM Configuration Integrity' \
            --status WARN --severity Medium --current "${#warns[@]} third-party or missing PAM module(s)" --details "${(F)warns}" "${fw[@]}" \
            --recommendation 'Confirm each listed module is expected (e.g. pam_tid.so for Touch ID in sudo_local is Apple; others should be known products), root-owned and not user-writable.'
    else
        add_audit_result --category 'Identity, Accounts & Privilege Management' --control 'PAM Configuration Integrity' \
            --status PASS --severity High --current 'Only Apple PAM modules, no pam_permit in authentication' "${fw[@]}" \
            --recommendation 'No action required.'
    fi
}

# ---------------------------------------------------------------- containers

check_container_runtime_exposure() {
    local entry="" home="" sock="" om="" target="" f=""
    local -a issues found
    local -a socks
    socks=(/var/run/docker.sock)
    for entry in "${(@f)$(_local_user_homes)}"; do
        [[ -z "$entry" ]] && continue
        home="${entry#*$'\t'}"
        socks+=("$home/.docker/run/docker.sock" "$home/.colima/default/docker.sock" "$home/.orbstack/run/docker.sock"
                "$home/.rd/docker.sock" "$home/.lima/default/sock/docker.sock")
        for f in "$home/Library/Group Containers/group.com.docker/settings.json" "$home/Library/Group Containers/group.com.docker/settings-store.json"; do
            [[ -f "$f" ]] || continue
            if grep -Eqi '"exposeDockerAPIOnTCP2375"[[:space:]]*:[[:space:]]*true' "$f" 2>/dev/null; then
                issues+=("${home:t}: Docker Desktop exposes the daemon on tcp://localhost:2375 without TLS (any local process or web page via DNS rebinding can run containers)")
            fi
        done
    done
    for sock in "${socks[@]}"; do
        [[ -S "$sock" || -L "$sock" ]] || continue
        target="$sock"
        [[ -L "$sock" ]] && target="${sock:A}"
        [[ -S "$target" ]] || continue
        found+=("$sock")
        om=$(_owner_mode "$target")
        _mode_group_or_other_writable "${om##* }" && issues+=("$sock -> $target ($om): other local users can drive the container engine as ${om%% *}")
    done
    local -a fw
    fw=(--recommended 'Container engine sockets usable only by their owner; no unauthenticated TCP API'
        --cis 'CIS 4.1' --nist 'AC-6, CM-7' --mitre 'T1610 (Deploy Container), T1611 (Escape to Host)'
        --iso27001 'A.8.20' --nis2 'Art.21(2)(e)' --cis-macos 'N/A' --mscp 'N/A')
    if (( ${#issues[@]} )); then
        add_audit_result --category 'Virtualization & Container Escape Surface' --control 'Container Engine Socket & API Exposure' \
            --status WARN --severity High --current "${#issues[@]} exposed container engine endpoint(s)" --details "${(F)issues}" "${fw[@]}" \
            --recommendation 'Turn off "Expose daemon on tcp://localhost:2375 without TLS" in Docker Desktop settings, and keep engine sockets owner-only (chmod 600 or 700 on the folder). Whoever can talk to the engine can mount the shared folders and run anything there.'
    else
        add_audit_result --category 'Virtualization & Container Escape Surface' --control 'Container Engine Socket & API Exposure' \
            --status PASS --severity High --current "${#found[@]} container engine socket(s), none exposed to other users or TCP" \
            --details "${(F)found}" "${fw[@]}" --recommendation 'No action required.'
    fi
}

# ---------------------------------------------------------------- SSH server

check_sshd_risky_options() {
    _sshd_query
    local cfg="$ROOT_CMD_OUTPUT" key="" val=""
    local -a issues
    local -A want
    # Option (lowercase, as sshd -G prints it) -> value that is safe.
    want=(permituserenvironment no permitemptypasswords no gatewayports no authorizedkeyscommand none
          authorizedprincipalscommand none permittunnel no)
    for key in ${(k)want}; do
        val=$(print -r -- "$cfg" | awk -v k="$key" 'tolower($1) == k { $1 = ""; sub(/^ /, ""); print; exit }')
        [[ -z "$val" || "${val:l}" == "${want[$key]}" ]] && continue
        case "$key" in
            permituserenvironment) issues+=("PermitUserEnvironment $val: users can set DYLD_*/LD_* for their own sshd session via ~/.ssh/environment") ;;
            permitemptypasswords) issues+=("PermitEmptyPasswords $val: accounts without a password can log in") ;;
            gatewayports) issues+=("GatewayPorts $val: forwarded ports are reachable from the network") ;;
            authorizedkeyscommand) issues+=("AuthorizedKeysCommand $val: an external program decides who may log in") ;;
            authorizedprincipalscommand) issues+=("AuthorizedPrincipalsCommand $val: an external program decides certificate principals") ;;
            permittunnel) issues+=("PermitTunnel $val: layer-3 tunnels into the network are allowed") ;;
        esac
    done
    if [[ "$SSHD_ENABLED" != 1 ]]; then
        add_audit_result --category 'SSH Server & Client Hardening' --control 'SSH Server Risky Options' \
            --status INFO --severity Informational \
            --current "Remote Login is off; ${#issues[@]} risky option(s) would apply if enabled" --details "${(F)issues}" \
            --recommended 'Harden before enabling Remote Login' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'Not scored while Remote Login (sshd) is off.'
        return
    fi
    local -a fw
    fw=(--recommended 'No user environment, empty passwords, gateway ports, tunnels or external key commands'
        --cis 'CIS 4.8' --nist 'AC-17, CM-6' --mitre 'T1021.004 (SSH), T1098.004 (SSH Authorized Keys)'
        --iso27001 'A.8.9' --nis2 'Art.21(2)(e)' --cis-macos 'N/A' --mscp 'N/A')
    if (( ${#issues[@]} )); then
        add_audit_result --category 'SSH Server & Client Hardening' --control 'SSH Server Risky Options' \
            --status WARN --severity Medium --current "${#issues[@]} risky sshd option(s)" --details "${(F)issues}" "${fw[@]}" \
            --recommendation 'Set the listed options back to their defaults in /etc/ssh/sshd_config.d/ (PermitUserEnvironment no, PermitEmptyPasswords no, GatewayPorts no, PermitTunnel no) and remove AuthorizedKeysCommand unless it is a known identity integration.'
    else
        add_audit_result --category 'SSH Server & Client Hardening' --control 'SSH Server Risky Options' \
            --status PASS --severity Medium --current 'No risky sshd options set' "${fw[@]}" --recommendation 'No action required.'
    fi
}

# ---------------------------------------------------------------- network listeners

check_network_exposed_listeners() {
    run_root lsof -nP -iTCP -sTCP:LISTEN -F pcn
    local line="" pid="" cmd="" name="" addr="" exe="" key=""
    local -a exposed
    local -A seen
    for line in "${(@f)ROOT_CMD_OUTPUT}"; do
        case "$line" in
            p*) pid="${line#p}" ;;
            c*) cmd="${line#c}" ;;
            n*)
                name="${line#n}"; addr="${name%:*}"
                [[ "$addr" == (127.*|\[::1\]|localhost|\[::ffff:127.*) ]] && continue
                [[ "$pid" == <-> ]] || continue
                exe=$(ps -p "$pid" -o comm= 2>/dev/null)
                [[ "$exe" == (/System/*|/usr/libexec/*|/usr/sbin/*|/usr/bin/*|/sbin/*|/bin/*) ]] && continue
                key="$cmd $name"
                [[ -n "${seen[$key]:-}" ]] && continue
                seen[$key]=1
                exposed+=("$cmd ($exe) on $name")
                ;;
        esac
    done
    # socketfilterfw, not /Library/Preferences/com.apple.alf: on macOS 15+ the application
    # firewall is a Network Extension filter and that plist no longer holds the live state.
    local fw_state="" fw_out=""
    fw_out=$("$SOCKETFILTERFW" --getglobalstate 2>&1)
    [[ "$fw_out" =~ 'State = ([0-9])' ]] && fw_state="${match[1]}"
    local -a fw
    fw=(--recommended 'Third-party services listen on loopback only, or are intended and firewalled'
        --cis 'CIS 4.4, 12.4' --nist 'CM-7, SC-7' --mitre 'T1133 (External Remote Services), T1210 (Exploitation of Remote Services)'
        --iso27001 'A.8.20' --nis2 'Art.21(2)(e)' --cis-macos 'N/A' --mscp 'N/A')
    if (( ${#exposed[@]} )); then
        add_audit_result --category 'System Services & Daemon Exposure' --control 'Third-Party Services Listening on the Network' \
            --status WARN --severity "$( [[ "$fw_state" == (1|2) ]] && print Low || print Medium )" \
            --current "${#exposed[@]} non-Apple listener(s) on non-loopback addresses (application firewall ${fw_state:-state unknown})" \
            --details "${(F)${(@o)exposed}}" "${fw[@]}" \
            --recommendation 'Confirm each listener should be reachable from the network. Bind development servers to 127.0.0.1, turn off sharing features you do not use, and keep the application firewall on so unexpected listeners are blocked.'
    else
        add_audit_result --category 'System Services & Daemon Exposure' --control 'Third-Party Services Listening on the Network' \
            --status PASS --severity Medium --current 'No non-Apple TCP listeners on network addresses' "${fw[@]}" \
            --recommendation 'No action required.'
    fi
}

# ---------------------------------------------------------------- shell history beyond the console user

# Bounded like the console-user sweep: the last 500 lines per file, counts only, never the
# matched text. Covers root and every other local user, plus database/REPL histories.
check_privileged_and_other_user_history_secrets() {
    local entry="" user="" home="" f="" line="" lower="" count=0
    local -a homes hits
    homes=("root"$'\t'"/var/root")
    for entry in "${(@f)$(_local_user_homes)}"; do
        [[ -z "$entry" ]] && continue
        [[ "${entry%%$'\t'*}" == "$CONSOLE_USER" ]] && continue   # covered by Shell History Secret Sweep
        homes+=("$entry")
    done
    for entry in "${homes[@]}"; do
        user="${entry%%$'\t'*}"; home="${entry#*$'\t'}"
        for f in .zsh_history .bash_history .sh_history .mysql_history .psql_history .python_history .node_repl_history; do
            run_root test -f "$home/$f"
            [[ $ROOT_CMD_STATUS -eq 0 ]] || continue
            run_root tail -n 500 "$home/$f"
            count=0
            for line in "${(@f)ROOT_CMD_OUTPUT}"; do
                lower="${line:l}"
                if [[ "$line" =~ 'AKIA[A-Z0-9]{16}' || "$line" == *"-----BEGIN"* || "$lower" == *(password=|passwd=|apikey=|api_key=|token=|secret=|identified\ by)* ]]; then
                    count=$((count + 1))
                fi
            done
            (( count > 0 )) && hits+=("$user: $count secret-like line(s) in ~/$f")
        done
    done
    local -a fw
    fw=(--recommended 'No secret-like patterns in root or other users'' shell and database histories'
        --cis 'CIS 3.11' --nist 'IA-5' --mitre 'T1552.003 (Bash History)' --iso27001 'A.8.24'
        --nis2 'Art.21(2)(h)' --cis-macos 'N/A' --mscp 'N/A')
    if (( ${#hits[@]} )); then
        add_audit_result --category 'Credential Exposure & Secret Leaks' --control 'Root & Other Users'' History Secret Sweep' \
            --status WARN --severity High --current "${#hits[@]} history file(s) with secret-like lines" --details "${(F)hits}" "${fw[@]}" \
            --recommendation 'Rotate any credential that was typed on a command line (root and database histories are read by anyone who later gains root), then clear the history entries. Prefer prompts or credential files over passwords in arguments.'
    else
        add_audit_result --category 'Credential Exposure & Secret Leaks' --control 'Root & Other Users'' History Secret Sweep' \
            --status PASS --severity High --current "No secret-like lines in ${#homes[@]} account(s)' recent histories" "${fw[@]}" \
            --recommendation 'No action required.'
    fi
}

# ---------------------------------------------------------------- library validation

check_library_validation_policy() {
    local plist="${1:-/Library/Preferences/com.apple.security.libraryvalidation.plist}" value=""
    value=$(defaults_read_safe "${plist%.plist}" DisableLibraryValidation '')
    local -a fw
    fw=(--recommended 'Library validation not disabled system-wide'
        --cis 'CIS 2.5' --nist 'SI-7, CM-7' --mitre 'T1574.006 (Dynamic Linker Hijacking), T1055 (Process Injection)'
        --iso27001 'A.8.19' --nis2 'Art.21(2)(e)' --cis-macos 'N/A' --mscp 'N/A')
    if [[ "${value:l}" == (1|true|yes) ]]; then
        add_audit_result --category 'Dylib Hijacking & Code Injection' --control 'Library Validation Disabled System-Wide' \
            --status FAIL --severity High --current "DisableLibraryValidation = $value" "${fw[@]}" \
            --recommendation 'Delete the setting: "sudo defaults delete /Library/Preferences/com.apple.security.libraryvalidation DisableLibraryValidation". With it, apps load unsigned plug-ins and libraries, so injected code inherits their TCC permissions and keychain access.'
    else
        add_audit_result --category 'Dylib Hijacking & Code Injection' --control 'Library Validation Disabled System-Wide' \
            --status PASS --severity High --current 'Not disabled (default)' "${fw[@]}" --recommendation 'No action required.'
    fi
}

# ---------------------------------------------------------------- download quarantine

check_download_quarantine_disabled() {
    local entry="" user="" home="" value=""
    local -a off
    for entry in "${(@f)$(_local_user_homes)}"; do
        [[ -z "$entry" ]] && continue
        user="${entry%%$'\t'*}"; home="${entry#*$'\t'}"
        # Read the file directly: defaults goes through cfprefsd, which special-cases
        # .../Library/Preferences paths outside the caller's own home.
        value=$(plutil -extract LSQuarantine raw -o - "$home/Library/Preferences/com.apple.LaunchServices.plist" 2>/dev/null)
        [[ "${value:l}" == (0|false|no) ]] && off+=("$user: LSQuarantine = $value")
    done
    local -a fw
    fw=(--recommended 'Downloads get the quarantine flag (LSQuarantine not disabled)'
        --cis 'CIS 2.6, 10.1' --nist 'SI-3, CM-7' --mitre 'T1553.001 (Gatekeeper Bypass)'
        --iso27001 'A.8.7' --nis2 'Art.21(2)(e)' --cis-macos 'N/A' --mscp 'N/A')
    if (( ${#off[@]} )); then
        add_audit_result --category 'Gatekeeper, Notarization & Application Control' --control 'Download Quarantine Disabled' \
            --status FAIL --severity High --current "Quarantine flag disabled for ${#off[@]} user(s)" --details "${(F)off}" "${fw[@]}" \
            --recommendation 'Remove the setting for each listed user: "defaults delete com.apple.LaunchServices LSQuarantine" (as that user). Without the quarantine flag, Gatekeeper never checks downloaded apps and scripts.'
    else
        add_audit_result --category 'Gatekeeper, Notarization & Application Control' --control 'Download Quarantine Disabled' \
            --status PASS --severity High --current 'Quarantine flag active for all users (default)' "${fw[@]}" --recommendation 'No action required.'
    fi
}

# ---------------------------------------------------------------- legacy VNC

check_legacy_vnc_password() {
    local vnc_file="${1:-/Library/Preferences/com.apple.VNCSettings.txt}" legacy=""
    local -a issues
    [[ -f "$vnc_file" ]] && issues+=("$vnc_file exists: a legacy VNC password (8 characters max, reversibly obfuscated) is set")
    legacy=$(defaults_read_safe /Library/Preferences/com.apple.RemoteManagement VNCLegacyConnectionsEnabled '')
    [[ "${legacy:l}" == (1|true|yes) ]] && issues+=("Remote Management: VNC viewers may control the screen with a password (VNCLegacyConnectionsEnabled)")
    local -a fw
    fw=(--recommended 'No legacy VNC password; screen sharing uses macOS account authentication'
        --cis 'CIS 4.6, 6.3' --nist 'IA-2, AC-17' --mitre 'T1021.005 (VNC)' --iso27001 'A.8.5'
        --nis2 'Art.21(2)(j)' --cis-macos 'N/A' --mscp 'N/A')
    if (( ${#issues[@]} )); then
        add_audit_result --category 'Remote Access & Sharing Services' --control 'Legacy VNC Password Authentication' \
            --status FAIL --severity High --current "${#issues[@]} legacy VNC setting(s)" --details "${(F)issues}" "${fw[@]}" \
            --recommendation 'In System Settings > General > Sharing > Screen Sharing (or Remote Management > Computer Settings), turn off "VNC viewers may control screen with password", then delete /Library/Preferences/com.apple.VNCSettings.txt. The VNC password is short, has no lockout and is stored reversibly.'
    else
        add_audit_result --category 'Remote Access & Sharing Services' --control 'Legacy VNC Password Authentication' \
            --status PASS --severity High --current 'No legacy VNC password configured' "${fw[@]}" --recommendation 'No action required.'
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

# ---- 90a-lada-glass-assets.zsh ----
#
# Låda Glass 1.1.1 assets for the HTML dashboard.
# Generated by build.sh from vendor/lada-glass/1.1.1. Do not edit; update the vendored copy instead.

typeset -g LADA_GLASS_VERSION='1.1.1'
typeset -g LADA_GLASS_CSS LADA_GLASS_SPRITE
read -r -d '' LADA_GLASS_CSS <<'LADA_GLASS_CSS_EOF'
/* Låda Glass 1.1.1: the shared look of Johan's apps (tools/design).
   Dark charcoal frosted glass is the main theme, light the alternative; compact density; custom
   accents. Values come from Låda (tokens.json); no build step, no dependencies, works from file://.

   Use:   <link rel="stylesheet" href="vendor/lada-glass/1.1.1/lada-glass.css">
   Bootstrap apps: also <link rel="stylesheet" href="vendor/lada-glass/1.1.1/lada-glass-bootstrap.css"> after it.
          <body class="lg lg-backdrop">  … components below …
   Theme:  follows the system; force one with <html data-theme="dark|light">.
   Accent: <html data-accent="arctic-teal" data-accent-2="aurora-green">, or set your own:
           :root { --lg-accent-d: #…; --lg-accent-l: #…; }  (d = dark theme, l = light theme)
   Density: compact by default; <html data-density="comfortable"> for more room.
   Everything is prefixed lg- so it doesn't collide with an app's own CSS. */

/* ---- tokens --------------------------------------------------------------------------------- */
:root {
  /* dark theme */
  --lg-bg-d: #141619;
  --lg-sidebar-d: #1B1E23;
  --lg-surface-d: #1E2127;
  --lg-elevated-d: #252930;
  --lg-code-d: #0F1217;
  --lg-text-d: #ECEEEF;
  --lg-muted-d: #8E96A2;
  --lg-border-d: #2C313A;
  --lg-ok-d: #47B577;
  --lg-warn-d: #E09B3D;
  --lg-bad-d: #E05A5A;
  --lg-ok-text-d: #50B97E;
  --lg-warn-text-d: #E09B3D;
  --lg-bad-text-d: #E78282;
  --lg-on-accent-d: #0F1217;
  --lg-backdrop-from-d: #11151B;
  --lg-backdrop-to-d: #181B21;
  /* light theme */
  --lg-bg-l: #F7F6F3;
  --lg-sidebar-l: #EFECE6;
  --lg-surface-l: #FCFBF9;
  --lg-elevated-l: #FFFFFF;
  --lg-code-l: #F5F7FA;
  --lg-text-l: #1A1D21;
  --lg-muted-l: #5C646E;
  --lg-border-l: #DFDDD7;
  --lg-ok-l: #2C8C58;
  --lg-warn-l: #B8741A;
  --lg-bad-l: #B83B3B;
  --lg-ok-text-l: #216A43;
  --lg-warn-text-l: #845413;
  --lg-bad-text-l: #A23434;
  --lg-on-accent-l: #FFFFFF;
  --lg-backdrop-from-l: #EAF0F5;
  --lg-backdrop-to-l: #F3F5F8;
  /* accents: fjord and frost-cyan by default */
  --lg-accent-d: #5A93C4; --lg-accent-l: #2B5B84;
  --lg-accent-2-d: #88C0D0; --lg-accent-2-l: #2A7288;
  /* spacing (4-pt scale), radii, type, motion */
  --lg-space-xxs: 2px; --lg-space-xs: 4px; --lg-space-s: 8px; --lg-space-m: 12px; --lg-space-l: 16px; --lg-space-xl: 24px; --lg-space-xxl: 32px;
  --lg-radius-control: 6px; --lg-radius-card: 10px;
  --lg-fs-body: 13px; --lg-fs-small: 11px; --lg-fs-label: 11px; --lg-fs-subtitle: 13px; --lg-fs-title: 18px; --lg-fs-kpi: 22px; --lg-fs-mono: 12px;
  --lg-dur-quick: 140ms; --lg-dur-standard: 320ms; --lg-dur-data: 350ms; --lg-dur-slow: 550ms;
  --lg-ease: cubic-bezier(.22, .61, .36, 1);
  --lg-ease-out: cubic-bezier(0, 0, .2, 1);
  --lg-touch: 44px;
  --lg-scale: 0.65;          /* panel insets: compact */
  --lg-row: 20px;
  --lg-font: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", system-ui, sans-serif;
  --lg-mono: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
  --lg-blur: blur(22px) saturate(150%);
}
:root[data-density="comfortable"], [data-density="comfortable"] { --lg-scale: 1; --lg-row: 28px; }

/* accent presets (Låda's accent themes) */
[data-accent="fjord"] { --lg-accent-d: #5A93C4; --lg-accent-l: #2B5B84; }
[data-accent="arctic-teal"] { --lg-accent-d: #459AA3; --lg-accent-l: #216B73; }
[data-accent="slate-steel"] { --lg-accent-d: #7D91A8; --lg-accent-l: #415164; }
[data-accent="frost-cyan"] { --lg-accent-d: #88C0D0; --lg-accent-l: #2A7288; }
[data-accent="aurora-green"] { --lg-accent-d: #A3BE8C; --lg-accent-l: #45763E; }
[data-accent="aurora-violet"] { --lg-accent-d: #B48EAD; --lg-accent-l: #714D88; }
[data-accent="lingonberry"] { --lg-accent-d: #D96E75; --lg-accent-l: #A83541; }
[data-accent="cloudberry"] { --lg-accent-d: #E0915C; --lg-accent-l: #AD591D; }
[data-accent="birch-gold"] { --lg-accent-d: #E1BC6D; --lg-accent-l: #8C6A16; }
[data-accent="midnight-indigo"] { --lg-accent-d: #8D95E3; --lg-accent-l: #41479C; }
[data-accent-2="fjord"] { --lg-accent-2-d: #5A93C4; --lg-accent-2-l: #2B5B84; }
[data-accent-2="arctic-teal"] { --lg-accent-2-d: #459AA3; --lg-accent-2-l: #216B73; }
[data-accent-2="slate-steel"] { --lg-accent-2-d: #7D91A8; --lg-accent-2-l: #415164; }
[data-accent-2="frost-cyan"] { --lg-accent-2-d: #88C0D0; --lg-accent-2-l: #2A7288; }
[data-accent-2="aurora-green"] { --lg-accent-2-d: #A3BE8C; --lg-accent-2-l: #45763E; }
[data-accent-2="aurora-violet"] { --lg-accent-2-d: #B48EAD; --lg-accent-2-l: #714D88; }
[data-accent-2="lingonberry"] { --lg-accent-2-d: #D96E75; --lg-accent-2-l: #A83541; }
[data-accent-2="cloudberry"] { --lg-accent-2-d: #E0915C; --lg-accent-2-l: #AD591D; }
[data-accent-2="birch-gold"] { --lg-accent-2-d: #E1BC6D; --lg-accent-2-l: #8C6A16; }
[data-accent-2="midnight-indigo"] { --lg-accent-2-d: #8D95E3; --lg-accent-2-l: #41479C; }

/* The active theme: dark unless the system asks for light; data-theme forces one (also on any
   element, e.g. a preview showing both). */
:root, [data-theme="dark"] {
  --lg-bg: var(--lg-bg-d);
  --lg-sidebar: var(--lg-sidebar-d);
  --lg-surface: var(--lg-surface-d);
  --lg-elevated: var(--lg-elevated-d);
  --lg-code: var(--lg-code-d);
  --lg-text: var(--lg-text-d);
  --lg-muted: var(--lg-muted-d);
  --lg-border: var(--lg-border-d);
  --lg-ok: var(--lg-ok-d);
  --lg-warn: var(--lg-warn-d);
  --lg-bad: var(--lg-bad-d);
  --lg-ok-text: var(--lg-ok-text-d);
  --lg-warn-text: var(--lg-warn-text-d);
  --lg-bad-text: var(--lg-bad-text-d);
  --lg-on-accent: var(--lg-on-accent-d);
  --lg-backdrop-from: var(--lg-backdrop-from-d);
  --lg-backdrop-to: var(--lg-backdrop-to-d);
  --lg-accent: var(--lg-accent-d);
  --lg-accent-2: var(--lg-accent-2-d);
  --lg-glass: rgba(30, 33, 39, 0.55);
  --lg-glass-strong: rgba(30, 33, 39, 0.78);
  --lg-line: rgba(255, 255, 255, .08);
  --lg-line-2: rgba(255, 255, 255, .15);
  --lg-field: rgba(255, 255, 255, .04);
  --lg-edge: linear-gradient(rgba(255, 255, 255, .14), rgba(255, 255, 255, .04));
  --lg-shadow: 0 4px 20px rgba(0, 0, 0, .28);
  --lg-glow: .30; --lg-glow-2: .18; --lg-art: rgba(255, 255, 255, .07);
  color-scheme: dark;
}
@media (prefers-color-scheme: light) {
  :root:not([data-theme="dark"]) {
  --lg-bg: var(--lg-bg-l);
  --lg-sidebar: var(--lg-sidebar-l);
  --lg-surface: var(--lg-surface-l);
  --lg-elevated: var(--lg-elevated-l);
  --lg-code: var(--lg-code-l);
  --lg-text: var(--lg-text-l);
  --lg-muted: var(--lg-muted-l);
  --lg-border: var(--lg-border-l);
  --lg-ok: var(--lg-ok-l);
  --lg-warn: var(--lg-warn-l);
  --lg-bad: var(--lg-bad-l);
  --lg-ok-text: var(--lg-ok-text-l);
  --lg-warn-text: var(--lg-warn-text-l);
  --lg-bad-text: var(--lg-bad-text-l);
  --lg-on-accent: var(--lg-on-accent-l);
  --lg-backdrop-from: var(--lg-backdrop-from-l);
  --lg-backdrop-to: var(--lg-backdrop-to-l);
  --lg-accent: var(--lg-accent-l);
  --lg-accent-2: var(--lg-accent-2-l);
  --lg-glass: rgba(252, 251, 249, 0.6);
  --lg-glass-strong: rgba(252, 251, 249, 0.82);
  --lg-line: rgba(20, 24, 32, .09);
  --lg-line-2: rgba(20, 24, 32, .16);
  --lg-field: rgba(20, 24, 32, .03);
  --lg-edge: linear-gradient(rgba(255, 255, 255, .85), rgba(0, 0, 0, .06));
  --lg-shadow: 0 4px 20px rgba(0, 0, 0, .07);
  --lg-glow: .26; --lg-glow-2: .22; --lg-art: rgba(30, 40, 60, .10);
  color-scheme: light;
  }
}
[data-theme="light"] {
  --lg-bg: var(--lg-bg-l);
  --lg-sidebar: var(--lg-sidebar-l);
  --lg-surface: var(--lg-surface-l);
  --lg-elevated: var(--lg-elevated-l);
  --lg-code: var(--lg-code-l);
  --lg-text: var(--lg-text-l);
  --lg-muted: var(--lg-muted-l);
  --lg-border: var(--lg-border-l);
  --lg-ok: var(--lg-ok-l);
  --lg-warn: var(--lg-warn-l);
  --lg-bad: var(--lg-bad-l);
  --lg-ok-text: var(--lg-ok-text-l);
  --lg-warn-text: var(--lg-warn-text-l);
  --lg-bad-text: var(--lg-bad-text-l);
  --lg-on-accent: var(--lg-on-accent-l);
  --lg-backdrop-from: var(--lg-backdrop-from-l);
  --lg-backdrop-to: var(--lg-backdrop-to-l);
  --lg-accent: var(--lg-accent-l);
  --lg-accent-2: var(--lg-accent-2-l);
  --lg-glass: rgba(252, 251, 249, 0.6);
  --lg-glass-strong: rgba(252, 251, 249, 0.82);
  --lg-line: rgba(20, 24, 32, .09);
  --lg-line-2: rgba(20, 24, 32, .16);
  --lg-field: rgba(20, 24, 32, .03);
  --lg-edge: linear-gradient(rgba(255, 255, 255, .85), rgba(0, 0, 0, .06));
  --lg-shadow: 0 4px 20px rgba(0, 0, 0, .07);
  --lg-glow: .26; --lg-glow-2: .22; --lg-art: rgba(30, 40, 60, .10);
  color-scheme: light;
}
/* ---- base ------------------------------------------------------------------------------------ */
.lg { font-family: var(--lg-font); font-size: var(--lg-fs-body); line-height: 1.45; color: var(--lg-text);
      background: var(--lg-bg); -webkit-font-smoothing: antialiased; text-size-adjust: 100%; }
.lg *, .lg *::before, .lg *::after { box-sizing: border-box; }
.lg :where(a) { color: var(--lg-accent); text-underline-offset: 2px; }  /* low specificity: .lg-btn* on a link wins */
.lg :focus-visible { outline: 2px solid var(--lg-accent); outline-offset: 2px; border-radius: var(--lg-radius-control); }
.lg ::selection { background: color-mix(in srgb, var(--lg-accent) 35%, transparent); }
.lg img, .lg svg { max-width: 100%; }

/* The calm backdrop the glass frosts: a soft gradient with two glows in the accent colours. */
.lg-backdrop { min-height: 100vh; background:
    radial-gradient(700px circle at 0 0, color-mix(in srgb, var(--lg-accent) calc(var(--lg-glow) * 100%), transparent), transparent 70%),
    radial-gradient(600px circle at 100% 100%, color-mix(in srgb, var(--lg-accent-2) calc(var(--lg-glow-2) * 100%), transparent), transparent 70%),
    linear-gradient(135deg, var(--lg-backdrop-from), var(--lg-backdrop-to));
  background-attachment: fixed; }
.lg-art { position: fixed; inset: auto -80px -80px auto; width: 420px; height: 420px; color: var(--lg-art);
          pointer-events: none; z-index: 0; }

/* ---- text ------------------------------------------------------------------------------------- */
.lg-title { font-size: var(--lg-fs-title); font-weight: 600; letter-spacing: -.01em; margin: 0 0 var(--lg-space-xs); }
.lg-subtitle { font-size: var(--lg-fs-subtitle); font-weight: 500; margin: 0 0 var(--lg-space-xs); }
.lg-label { font-size: var(--lg-fs-label); font-weight: 600; letter-spacing: .08em; text-transform: uppercase;
            color: var(--lg-muted); margin: 0 0 var(--lg-space-s); }
.lg-muted { color: var(--lg-muted); }
.lg-small { font-size: var(--lg-fs-small); }
.lg-mono, .lg code { font-family: var(--lg-mono); font-size: var(--lg-fs-mono); }
.lg-code { font-family: var(--lg-mono); font-size: var(--lg-fs-mono); background: var(--lg-code); color: var(--lg-text);
           border: 1px solid var(--lg-line); border-radius: var(--lg-radius-control); padding: var(--lg-space-s) var(--lg-space-m);
           overflow-x: auto; }

/* ---- glass surfaces ------------------------------------------------------------------------------ */
.lg-glass, .lg-card, .lg-sidebar, .lg-toast, .lg-popup, .lg-empty {
  position: relative; background: var(--lg-glass); -webkit-backdrop-filter: var(--lg-blur); backdrop-filter: var(--lg-blur);
  border-radius: var(--lg-radius-card); box-shadow: var(--lg-shadow); }
/* the fine light edge (a gradient border) */
.lg-glass::after, .lg-card::after, .lg-sidebar::after, .lg-toast::after, .lg-popup::after, .lg-empty::after {
  content: ""; position: absolute; inset: 0; border-radius: inherit; padding: 1px; pointer-events: none;
  background: var(--lg-edge); -webkit-mask: linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0);
  -webkit-mask-composite: xor; mask-composite: exclude; }
.lg-card { padding: calc(var(--lg-space-l) * var(--lg-scale) + 2px); }
.lg-card.lg-hover { transition: transform var(--lg-dur-quick) var(--lg-ease-out), box-shadow var(--lg-dur-quick) var(--lg-ease-out); }
.lg-card.lg-hover:hover { transform: translateY(-1px); box-shadow: var(--lg-shadow), 0 0 0 1px color-mix(in srgb, var(--lg-accent) 45%, transparent); }
@supports not ((backdrop-filter: blur(1px)) or (-webkit-backdrop-filter: blur(1px))) {
  .lg-glass, .lg-card, .lg-sidebar, .lg-toast, .lg-popup, .lg-empty { background: var(--lg-surface); }
}

/* ---- layout: app shell, stack, row, responsive grid ----------------------------------------------- */
.lg-app { position: relative; z-index: 1; display: grid; grid-template-columns: 200px minmax(0, 1fr);
          gap: var(--lg-space-m); padding: var(--lg-space-m); min-height: 100vh; align-items: start; }
.lg-sidebar { position: sticky; top: var(--lg-space-m); padding: var(--lg-space-s); background: var(--lg-glass-strong); }
.lg-brand { display: flex; align-items: center; gap: var(--lg-space-s); font-weight: 600; padding: var(--lg-space-xs) var(--lg-space-s) var(--lg-space-m); }
.lg-nav { display: grid; gap: var(--lg-space-xxs); }
.lg-nav a { display: flex; align-items: center; gap: var(--lg-space-s); padding: 5px var(--lg-space-s); border-radius: var(--lg-radius-control);
            color: var(--lg-muted); text-decoration: none; min-height: 28px; white-space: nowrap;
            transition: background var(--lg-dur-quick) var(--lg-ease-out), color var(--lg-dur-quick) var(--lg-ease-out); }
.lg-nav a:hover { background: var(--lg-field); color: var(--lg-text); }
.lg-nav a[aria-current="page"] { background: color-mix(in srgb, var(--lg-accent) 16%, transparent); color: var(--lg-text); }
.lg-nav a[aria-current="page"] .lg-icon { color: var(--lg-accent); }
.lg-main { min-width: 0; display: grid; grid-template-columns: minmax(0, 1fr); gap: var(--lg-space-m); }
.lg-header { display: flex; align-items: center; justify-content: space-between; gap: var(--lg-space-m); flex-wrap: wrap; }
.lg-stack { display: grid; grid-template-columns: minmax(0, 1fr); gap: var(--lg-space-m); }
.lg-row { display: flex; gap: var(--lg-space-s); flex-wrap: wrap; align-items: center; }
.lg-grid { display: grid; gap: var(--lg-space-m); grid-template-columns: repeat(auto-fit, minmax(min(100%, var(--lg-col, 200px)), 1fr)); }
/* Phones: the sidebar becomes a top bar whose menu scrolls sideways (never the page). */
@media (max-width: 760px) {
  .lg-app { grid-template-columns: minmax(0, 1fr); padding: var(--lg-space-s); gap: var(--lg-space-s); }
  .lg-sidebar { position: static; display: flex; align-items: center; gap: var(--lg-space-s); min-width: 0; }
  .lg-brand { padding: var(--lg-space-xs); }
  .lg-nav { display: flex; overflow-x: auto; scrollbar-width: none; min-width: 0; }
  .lg-sidebar .lg-label { display: none; }
}

/* ---- controls ------------------------------------------------------------------------------------ */
.lg-btn { display: inline-flex; align-items: center; justify-content: center; gap: var(--lg-space-xs);
          font: inherit; font-weight: 600; line-height: 1.2; padding: 6px 12px; min-height: 28px; cursor: pointer;
          border-radius: var(--lg-radius-control); border: 1px solid var(--lg-line-2); background: var(--lg-field); color: var(--lg-text);
          text-decoration: none;
          transition: transform var(--lg-dur-quick) var(--lg-ease-out), filter var(--lg-dur-quick), background var(--lg-dur-quick), border-color var(--lg-dur-quick); }
.lg-btn:hover { border-color: color-mix(in srgb, var(--lg-accent) 55%, var(--lg-line-2)); }
.lg-btn:active { transform: scale(.98); }
.lg-btn:disabled, .lg-btn[aria-disabled="true"] { opacity: .5; cursor: not-allowed; transform: none; }
.lg-btn-primary { background: var(--lg-accent); border-color: transparent; color: var(--lg-on-accent); }
.lg-btn-primary:hover { filter: brightness(1.07); border-color: transparent; }
.lg-btn-ghost { background: transparent; border-color: transparent; color: var(--lg-accent); }
.lg-btn-danger { background: color-mix(in srgb, var(--lg-bad) 15%, transparent); border-color: transparent; color: var(--lg-bad-text); }
.lg-btn-icon { padding: 5px; min-width: 28px; }

.lg-input { font: inherit; color: var(--lg-text); background: var(--lg-field); border: 1px solid var(--lg-line-2);
            border-radius: var(--lg-radius-control); padding: 5px 9px; min-height: 28px; width: 100%; max-width: 100%;
            transition: border-color var(--lg-dur-quick), box-shadow var(--lg-dur-quick); }
.lg-input::placeholder { color: var(--lg-muted); opacity: 1; }
.lg-input:focus { outline: none; border-color: var(--lg-accent); box-shadow: 0 0 0 3px color-mix(in srgb, var(--lg-accent) 25%, transparent); }
textarea.lg-input { min-height: 72px; resize: vertical; }
.lg-field { display: grid; gap: var(--lg-space-xs); }
.lg-field > label { font-weight: 500; }

.lg-tabs { display: inline-flex; gap: 2px; padding: 3px; background: var(--lg-field); border: 1px solid var(--lg-line);
           border-radius: var(--lg-radius-control); max-width: 100%; overflow-x: auto; }
.lg-tab { font: inherit; border: 0; background: transparent; color: var(--lg-muted); padding: 4px 11px; border-radius: 4px; cursor: pointer;
          white-space: nowrap; transition: background var(--lg-dur-quick), color var(--lg-dur-quick); }
.lg-tab:hover { color: var(--lg-text); }
.lg-tab[aria-selected="true"] { background: var(--lg-glass-strong); color: var(--lg-text); box-shadow: 0 1px 3px rgba(0, 0, 0, .15); }

.lg-toggle { appearance: none; -webkit-appearance: none; width: 34px; height: 20px; border-radius: 999px; margin: 0; cursor: pointer;
             background: var(--lg-line-2); position: relative; flex: none; transition: background var(--lg-dur-quick) var(--lg-ease-out); }
.lg-toggle::after { content: ""; position: absolute; left: 3px; top: 3px; width: 14px; height: 14px; border-radius: 50%; background: #fff;
                    box-shadow: 0 1px 2px rgba(0, 0, 0, .3); transition: transform var(--lg-dur-quick) var(--lg-ease-out); }
.lg-toggle:checked { background: var(--lg-accent); }
.lg-toggle:checked::after { transform: translateX(14px); }

.lg-chip { display: inline-flex; align-items: center; gap: 5px; font-size: var(--lg-fs-small); font-weight: 500; line-height: 1.5;
           padding: 1px 8px; border-radius: 999px; color: var(--lg-muted); background: color-mix(in srgb, var(--lg-muted) 15%, transparent); }
.lg-chip::before { content: ""; width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
.lg-chip.lg-ok   { color: var(--lg-ok-text);   background: color-mix(in srgb, var(--lg-ok) 15%, transparent); }
.lg-chip.lg-warn { color: var(--lg-warn-text); background: color-mix(in srgb, var(--lg-warn) 15%, transparent); }
.lg-chip.lg-bad  { color: var(--lg-bad-text);  background: color-mix(in srgb, var(--lg-bad) 15%, transparent); }
.lg-chip.lg-ok::before { background: var(--lg-ok); } .lg-chip.lg-warn::before { background: var(--lg-warn); } .lg-chip.lg-bad::before { background: var(--lg-bad); }
.lg-chip.lg-plain::before { display: none; }

/* ---- data ------------------------------------------------------------------------------------- */
.lg-kpi .lg-kpi-value { font-size: var(--lg-fs-kpi); font-weight: 650; letter-spacing: -.02em; line-height: 1.1; margin-top: var(--lg-space-xs);
                        font-variant-numeric: tabular-nums; }
.lg-table-wrap { overflow-x: auto; max-width: 100%; }
.lg-table { width: 100%; border-collapse: collapse; }
.lg-table th { text-align: left; font-size: var(--lg-fs-label); font-weight: 600; letter-spacing: .07em; text-transform: uppercase;
               color: var(--lg-muted); padding: 5px 8px; border-bottom: 1px solid var(--lg-line); white-space: nowrap; }
.lg-table td { padding: 5px 8px; border-bottom: 1px solid var(--lg-line); height: var(--lg-row); }
.lg-table tr:last-child td { border-bottom: 0; }
.lg-table tbody tr { transition: background var(--lg-dur-quick); }
.lg-table tbody tr:hover { background: color-mix(in srgb, var(--lg-text) 5%, transparent); }
.lg-num { text-align: right; font-variant-numeric: tabular-nums; }

/* ---- feedback ----------------------------------------------------------------------------------- */
.lg-toast { display: flex; gap: var(--lg-space-s); align-items: flex-start; padding: var(--lg-space-s) var(--lg-space-m);
            border-left: 3px solid var(--lg-accent); max-width: 420px; }
.lg-toast.lg-ok { border-left-color: var(--lg-ok); } .lg-toast.lg-warn { border-left-color: var(--lg-warn); } .lg-toast.lg-bad { border-left-color: var(--lg-bad); }
.lg-toast strong { display: block; }
.lg-empty { text-align: center; padding: var(--lg-space-xl) var(--lg-space-m); color: var(--lg-muted); }
.lg-empty > svg { width: 88px; height: 88px; color: var(--lg-art); display: block; margin: 0 auto var(--lg-space-s); }
.lg-empty strong { color: var(--lg-text); display: block; margin-bottom: var(--lg-space-xxs); }

/* ---- browser-extension popup ----------------------------------------------------------------------- */
.lg-popup { width: 360px; max-width: 100%; padding: calc(var(--lg-space-l) * var(--lg-scale) + 4px); }
.lg-mark { width: 28px; height: 28px; border-radius: 8px; display: grid; place-items: center; flex: none;
           background: color-mix(in srgb, var(--lg-accent) 22%, transparent); color: var(--lg-accent); }

/* ---- icons ------------------------------------------------------------------------------------- */
.lg-icon { width: 16px; height: 16px; flex: none; fill: none; stroke: currentColor; stroke-width: 1.7;
           stroke-linecap: round; stroke-linejoin: round; vertical-align: -3px; }
.lg-icon-l { width: 20px; height: 20px; }

/* ---- motion ------------------------------------------------------------------------------------- */
/* Quick micro-animations (hover, press) use --lg-dur-quick; larger changes are slow and smooth. Content
   never depends on them: .lg-enter only moves, it never starts invisible. */
.lg-enter { animation: lg-rise var(--lg-dur-slow) var(--lg-ease) both; }
@keyframes lg-rise { from { transform: translateY(8px); } to { transform: none; } }
.lg-fade { transition: opacity var(--lg-dur-slow) var(--lg-ease), transform var(--lg-dur-slow) var(--lg-ease); }

/* ---- touch: 44 px targets on touch screens, compact look on desktop ------------------------------------- */
@media (pointer: coarse) {
  .lg-btn, .lg-input, .lg-nav a, .lg-tab { min-height: var(--lg-touch); }
  .lg-btn-icon { min-width: var(--lg-touch); }
  .lg-toggle { width: 44px; height: 26px; } .lg-toggle::after { width: 20px; height: 20px; } .lg-toggle:checked::after { transform: translateX(18px); }
}

/* ---- accessibility preferences ------------------------------------------------------------------- */
@media (prefers-reduced-motion: reduce) {
  .lg, .lg *, .lg *::before, .lg *::after { animation: none !important; transition-duration: 1ms !important; scroll-behavior: auto !important; }
}
@media (prefers-reduced-transparency: reduce) {
  .lg-glass, .lg-card, .lg-sidebar, .lg-toast, .lg-popup, .lg-empty { background: var(--lg-surface); -webkit-backdrop-filter: none; backdrop-filter: none; }
  .lg-backdrop { background: var(--lg-bg); }
}
@media (forced-colors: active) {
  .lg-glass, .lg-card, .lg-sidebar, .lg-toast, .lg-popup, .lg-empty { border: 1px solid CanvasText; }
  .lg-toggle { border: 1px solid CanvasText; }
}
@media print {
  .lg-backdrop { background: none; }
  .lg-glass, .lg-card, .lg-sidebar, .lg-toast, .lg-popup, .lg-empty { background: none; box-shadow: none; border: 1px solid #999; }
}

/* An inlined icon sprite (icons/sprite.svg) takes no space. */
.lg-sprite { position: absolute; width: 0; height: 0; overflow: hidden; }
LADA_GLASS_CSS_EOF
read -r -d '' LADA_GLASS_SPRITE <<'LADA_GLASS_SPRITE_EOF'
<svg xmlns="http://www.w3.org/2000/svg" class="lg-sprite" aria-hidden="true" style="display:none">
<symbol id="activity" viewBox="0 0 24 24"><path d="M3 12h4l2.5-6 5 12 2.5-6h4"/></symbol>
<symbol id="alert" viewBox="0 0 24 24"><path d="M12 3.5l9.5 16.5h-19L12 3.5z"/><path d="M12 10v4.5M12 17.5v.01"/></symbol>
<symbol id="app" viewBox="0 0 24 24"><rect x="3.5" y="4.5" width="17" height="15" rx="2.5"/><path d="M3.5 10.5h17M12 4.5v6M9.5 15h5"/></symbol>
<symbol id="box" viewBox="0 0 24 24"><path d="M12 3l8 4.5v9L12 21l-8-4.5v-9L12 3z"/><path d="M12 12l8-4.5M12 12v9M12 12L4 7.5"/></symbol>
<symbol id="bug" viewBox="0 0 24 24"><rect x="7.5" y="7.5" width="9" height="12" rx="4.5"/><path d="M12 11.5v8M9 7.5a3 3 0 0 1 6 0M3.5 13h4M16.5 13h4M4.5 8.5l3 2M19.5 8.5l-3 2M4.5 19l3-2.5M19.5 19l-3-2.5"/></symbol>
<symbol id="chart" viewBox="0 0 24 24"><path d="M4 20V10M10 20V4M16 20v-7M21 20H3"/></symbol>
<symbol id="check" viewBox="0 0 24 24"><path d="M5 12.5l4.5 4.5L19 7.5"/></symbol>
<symbol id="check-circle" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M8 12.5l3 3 5-6"/></symbol>
<symbol id="chevron-down" viewBox="0 0 24 24"><path d="M6 9.5l6 6 6-6"/></symbol>
<symbol id="chevron-right" viewBox="0 0 24 24"><path d="M9.5 6l6 6-6 6"/></symbol>
<symbol id="clock" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3.5 2"/></symbol>
<symbol id="copy" viewBox="0 0 24 24"><rect x="8.5" y="8.5" width="12" height="12" rx="2"/><path d="M15.5 8.5V5.5a2 2 0 0 0-2-2h-8a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h3"/></symbol>
<symbol id="download" viewBox="0 0 24 24"><path d="M12 4v11.5M7.5 11L12 15.5 16.5 11M4 15v3a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-3"/></symbol>
<symbol id="edit" viewBox="0 0 24 24"><path d="M4 20l1-4.5L15.5 5a2 2 0 0 1 3 0l.5.5a2 2 0 0 1 0 3L8.5 19 4 20z"/><path d="M13.5 7l3.5 3.5"/></symbol>
<symbol id="external" viewBox="0 0 24 24"><path d="M14 4h6v6M20 4l-9 9M18 14v4.5a1.5 1.5 0 0 1-1.5 1.5h-11A1.5 1.5 0 0 1 4 18.5v-11A1.5 1.5 0 0 1 5.5 6H10"/></symbol>
<symbol id="eye" viewBox="0 0 24 24"><path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z"/><circle cx="12" cy="12" r="3"/></symbol>
<symbol id="file" viewBox="0 0 24 24"><path d="M13.5 3.5H7a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V9l-5.5-5.5z"/><path d="M13.5 3.5V9H19"/></symbol>
<symbol id="filter" viewBox="0 0 24 24"><path d="M4 5h16l-6 7.5V19l-4 1.5v-8L4 5z"/></symbol>
<symbol id="folder" viewBox="0 0 24 24"><path d="M3.5 7a2 2 0 0 1 2-2h4l2 2.5h7a2 2 0 0 1 2 2V17a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2V7z"/></symbol>
<symbol id="globe" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.6 3.7 5.6 3.7 9S14.5 18.4 12 21c-2.5-2.6-3.7-5.6-3.7-9S9.5 5.6 12 3z"/></symbol>
<symbol id="info" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 11v5.5M12 7.5v.01"/></symbol>
<symbol id="key" viewBox="0 0 24 24"><circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M16.5 6.5l2.5 2.5M14 9l2 2"/></symbol>
<symbol id="layers" viewBox="0 0 24 24"><path d="M4 8l8-4 8 4-8 4-8-4z"/><path d="M4 12l8 4 8-4M4 16l8 4 8-4"/></symbol>
<symbol id="link" viewBox="0 0 24 24"><path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/></symbol>
<symbol id="list" viewBox="0 0 24 24"><path d="M9 6h11M9 12h11M9 18h11"/><circle cx="4.5" cy="6" r=".6"/><circle cx="4.5" cy="12" r=".6"/><circle cx="4.5" cy="18" r=".6"/></symbol>
<symbol id="lock" viewBox="0 0 24 24"><rect x="5" y="10.5" width="14" height="10" rx="2"/><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3"/></symbol>
<symbol id="mail" viewBox="0 0 24 24"><rect x="3" y="5.5" width="18" height="13" rx="2"/><path d="M3.5 7l8.5 6 8.5-6"/></symbol>
<symbol id="menu" viewBox="0 0 24 24"><path d="M4 7h16M4 12h16M4 17h16"/></symbol>
<symbol id="minus" viewBox="0 0 24 24"><path d="M5 12h14"/></symbol>
<symbol id="moon" viewBox="0 0 24 24"><path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z"/></symbol>
<symbol id="overview" viewBox="0 0 24 24"><rect x="3.5" y="3.5" width="7" height="7" rx="1.5"/><rect x="13.5" y="3.5" width="7" height="7" rx="1.5"/><rect x="3.5" y="13.5" width="7" height="7" rx="1.5"/><rect x="13.5" y="13.5" width="7" height="7" rx="1.5"/></symbol>
<symbol id="plus" viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></symbol>
<symbol id="refresh" viewBox="0 0 24 24"><path d="M20 11a8 8 0 0 0-14.5-4.5L4 8M4 4v4h4M4 13a8 8 0 0 0 14.5 4.5L20 16M20 20v-4h-4"/></symbol>
<symbol id="scan" viewBox="0 0 24 24"><path d="M8 3.5H5.5a2 2 0 0 0-2 2V8M16 3.5h2.5a2 2 0 0 1 2 2V8M8 20.5H5.5a2 2 0 0 1-2-2V16M16 20.5h2.5a2 2 0 0 0 2-2V16M7 12h10"/></symbol>
<symbol id="search" viewBox="0 0 24 24"><circle cx="11" cy="11" r="6.5"/><path d="M20 20l-4.2-4.2"/></symbol>
<symbol id="settings" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M12 2.5v3M12 18.5v3M2.5 12h3M18.5 12h3M5.3 5.3l2.1 2.1M16.6 16.6l2.1 2.1M5.3 18.7l2.1-2.1M16.6 7.4l2.1-2.1"/></symbol>
<symbol id="shield" viewBox="0 0 24 24"><path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z"/></symbol>
<symbol id="shield-check" viewBox="0 0 24 24"><path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z"/><path d="M9 12l2 2 4-4"/></symbol>
<symbol id="sun" viewBox="0 0 24 24"><circle cx="12" cy="12" r="4"/><path d="M12 2.5v2M12 19.5v2M2.5 12h2M19.5 12h2M5.3 5.3l1.4 1.4M17.3 17.3l1.4 1.4M5.3 18.7l1.4-1.4M17.3 6.7l1.4-1.4"/></symbol>
<symbol id="terminal" viewBox="0 0 24 24"><rect x="3" y="4.5" width="18" height="15" rx="2"/><path d="M7 9.5l3 2.5-3 2.5M12.5 15h4.5"/></symbol>
<symbol id="trash" viewBox="0 0 24 24"><path d="M4 6.5h16M9.5 6.5V4.5h5v2M6.5 6.5l1 13a1.5 1.5 0 0 0 1.5 1.5h6a1.5 1.5 0 0 0 1.5-1.5l1-13M10 10.5v6M14 10.5v6"/></symbol>
<symbol id="upload" viewBox="0 0 24 24"><path d="M12 15.5V4M7.5 8.5L12 4l4.5 4.5M4 15v3a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-3"/></symbol>
<symbol id="user" viewBox="0 0 24 24"><circle cx="12" cy="8" r="4"/><path d="M4.5 20.5a7.5 7.5 0 0 1 15 0"/></symbol>
<symbol id="x" viewBox="0 0 24 24"><path d="M6 6l12 12M18 6L6 18"/></symbol>
</svg>
LADA_GLASS_SPRITE_EOF

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
    # "macOS 26.1 (25B78)" rather than the raw "ProductName: ... BuildVersion: ..." lines.
    osinfo=$(print -r -- "$ROOT_CMD_OUTPUT" | awk -F':[[:space:]]*' '
        /^ProductName/ { n = $2 } /^ProductVersion/ { v = $2 } /^BuildVersion/ { b = $2 }
        END { if (n != "") printf "%s %s%s", n, v, (b != "" ? " (" b ")" : "") }')
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
    # "14G used of 995G (6%)" from df's size/used/capacity columns.
    disk_line=$(print -r -- "$ROOT_CMD_OUTPUT" | awk 'NR == 2 { printf "%s used of %s (%s)", $3, $2, $5 }')
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
        # Named status_val, not status (zsh's read-only alias for $?), and
        # every local initialized with ="" (re-running a bare `local x` on a
        # set name prints "x=value" into the output).
        local status_val="${AUDIT_STATUS[$i]}" severity="${AUDIT_SEVERITY[$i]}"
        local control_esc="" category_esc="" current_esc="" details_esc="" recommended_esc="" recommendation_esc=""
        control_esc=$(html_escape "${AUDIT_CONTROL[$i]}")
        category_esc=$(html_escape "${AUDIT_CATEGORY[$i]}")
        current_esc=$(html_escape "${AUDIT_CURRENT[$i]}")
        details_esc=$(html_escape "${AUDIT_DETAILS[$i]}")
        recommended_esc=$(html_escape "${AUDIT_RECOMMENDED[$i]}")
        recommendation_esc=$(html_escape "${AUDIT_RECOMMENDATION[$i]}")

        # A finding with an item list gets a focusable button that opens a
        # frosted popover with one item per line (hover, focus or click).
        local measured_value="$current_esc"
        if [[ -n "$details_esc" ]]; then
            measured_value="<button type=\"button\" class=\"pc-tip\" data-tip=\"$details_esc\">$current_esc<svg class=\"lg-icon\" aria-hidden=\"true\"><use href=\"#list\"/></svg><span class=\"pc-sr\"> (show list)</span></button>"
        fi
        local search_blob=""
        search_blob=$(html_escape "$(print -r -- "${AUDIT_CONTROL[$i]} ${AUDIT_CATEGORY[$i]} ${AUDIT_CURRENT[$i]} ${AUDIT_RECOMMENDATION[$i]}" | tr '[:upper:]' '[:lower:]')")

        local status_tone="" severity_tone="lg-plain"
        case "$status_val" in
            PASS) status_tone="lg-ok" ;;
            FAIL) status_tone="lg-bad" ;;
            WARN) status_tone="lg-warn" ;;
        esac
        # Severity is colored only where it matters: on a FAIL or WARN.
        if [[ "$status_val" == FAIL || "$status_val" == WARN ]]; then
            case "$severity" in
                Critical) severity_tone="lg-bad" ;;
                High) severity_tone="lg-warn" ;;
            esac
        fi

        local chips="" cd=""
        local -a chip_defs
        chip_defs=(
            "CIS:${AUDIT_CIS[$i]}" "NIST:${AUDIT_NIST[$i]}" "MITRE:${AUDIT_MITRE[$i]}"
            "ISO 27001:${AUDIT_ISO27001[$i]}" "NIS2:${AUDIT_NIS2[$i]}" "NSA:${AUDIT_NSA[$i]}"
            "CIS-macOS:${AUDIT_CISMACOS[$i]}" "mSCP:${AUDIT_MSCP[$i]}"
        )
        for cd in "${chip_defs[@]}"; do
            local label="${cd%%:*}" val="${cd#*:}"
            if [[ -n "$val" && "$val" != "N/A" ]]; then
                val="${val#CIS-macOS }"; val="${val#$label }"   # "CIS CIS 4.8" -> "CIS 4.8"
                chips+="<span class=\"lg-chip lg-plain pc-fw-chip\"><b>$(html_escape "$label")</b> $(html_escape "$val")</span>"
            fi
        done
        [[ -z "$chips" ]] && chips='<span class="lg-muted lg-small">None</span>'

        rows+="<tr class=\"finding-row\" data-status=\"$status_val\" data-severity=\"$severity\" data-category=\"$category_esc\" data-search=\"$search_blob\">"
        rows+="<td data-label=\"Control\"><strong>$control_esc</strong><span class=\"pc-sub lg-muted lg-small\">$category_esc</span></td>"
        rows+="<td data-label=\"Status\"><span class=\"lg-chip $status_tone\">$status_val</span></td>"
        rows+="<td data-label=\"Severity\"><span class=\"lg-chip $severity_tone\">$severity</span></td>"
        rows+="<td data-label=\"Measured / Expected\"><div class=\"pc-mv\"><span class=\"lg-label\">Measured</span>$measured_value</div><div class=\"pc-mv\"><span class=\"lg-label\">Expected</span><span class=\"lg-muted\">$recommended_esc</span></div></td>"
        rows+="<td data-label=\"Frameworks\"><div class=\"pc-fw\">$chips</div></td>"
        rows+="<td data-label=\"Remediation\" class=\"pc-remed\">$recommendation_esc</td>"
        rows+="</tr>"
    done
    print -r -- "$rows"
}

# Sidebar domain list: one link per category in report order, with a red
# or amber count of its FAIL/WARN findings. Clicking filters the table.
_domain_nav_links() {
    local i="" cat="" links=""
    local -a order
    local -A fails warns
    for (( i = 1; i <= ${#AUDIT_CATEGORY[@]}; i++ )); do
        cat="${AUDIT_CATEGORY[$i]}"
        (( ${order[(Ie)$cat]} )) || order+=("$cat")
        case "${AUDIT_STATUS[$i]}" in
            FAIL) fails[$cat]=$(( ${fails[$cat]:-0} + 1 )) ;;
            WARN) warns[$cat]=$(( ${warns[$cat]:-0} + 1 )) ;;
        esac
    done
    local cat_esc="" badge=""
    for cat in "${order[@]}"; do
        cat_esc=$(html_escape "$cat")
        badge=""
        if (( ${fails[$cat]:-0} > 0 )); then
            badge="<span class=\"lg-chip lg-bad\" title=\"FAIL findings\">${fails[$cat]}</span>"
        elif (( ${warns[$cat]:-0} > 0 )); then
            badge="<span class=\"lg-chip lg-warn\" title=\"WARN findings\">${warns[$cat]}</span>"
        fi
        links+="<a href=\"#findings\" data-category=\"$cat_esc\"><span>$cat_esc</span>$badge</a>"$'\n'
    done
    print -r -- "$links"
}

get_html_template() {
    cat <<'HTMLTEMPLATE_EOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="color-scheme" content="dark light">
<title>EndpointPostureCheck - {{COMPUTERNAME}}</title>
<style>
{{LADA_CSS}}
/* ---- EndpointPostureCheck dashboard (on top of Lada Glass) ---- */
.lg-app { max-width: 1680px; margin: 0 auto; }
@media (min-width: 761px) {
  .lg-app { grid-template-columns: 240px minmax(0, 1fr); }  /* phones keep the design system's top bar */
  /* The sidebar is one viewport tall and scrolls on its own: with 32 domains it is taller than
     the window, and a sticky element taller than the viewport cannot show its end and slides away
     when filtering shortens the page (measured: 1344 px sidebar in a 900 px window). */
  .lg-sidebar { max-height: calc(100vh - 2 * var(--lg-space-m)); overflow-y: auto; overscroll-behavior: contain;
                scrollbar-width: thin; scrollbar-color: var(--lg-line-2) transparent; }
  .lg-main { min-height: calc(100vh - 2 * var(--lg-space-m)); }
}
#sec-overview, #system, #findings { scroll-margin-top: var(--lg-space-m); }
#findings { min-height: min(80vh, 720px); align-content: start; }   /* filtering never collapses the page */
@media (prefers-reduced-motion: no-preference) { html { scroll-behavior: smooth; } }
.pc-filter-chip { display: inline-flex; align-items: center; gap: 4px; font: inherit; font-size: var(--lg-fs-small);
                  border: 1px solid color-mix(in srgb, var(--lg-accent) 45%, transparent); cursor: pointer;
                  background: color-mix(in srgb, var(--lg-accent) 14%, transparent); color: var(--lg-text);
                  border-radius: 999px; padding: 1px 4px 1px 9px; }
.pc-filter-chip .lg-icon { width: 14px; height: 14px; }
.pc-domains a { white-space: normal; line-height: 1.25; justify-content: space-between; font-size: var(--lg-fs-small); min-height: 24px; }
.pc-domains .lg-chip { flex: none; }
.lg-nav a[aria-current="location"] { background: color-mix(in srgb, var(--lg-accent) 16%, transparent); color: var(--lg-text); }
.lg-nav a[aria-current="location"] .lg-icon { color: var(--lg-accent); }
.pc-score { display: flex; align-items: center; gap: var(--lg-space-l); }
@media (min-width: 561px) { .pc-span2 { grid-column: span 2; } }
@media (max-width: 560px) { .pc-span2 { grid-column: 1 / -1; } }
.pc-ring { --pc-tone: var(--lg-accent); width: 92px; height: 92px; flex: none; border-radius: 50%; display: grid; place-items: center;
           background: conic-gradient(var(--pc-tone) calc(var(--pc-deg) * 1deg), var(--lg-line-2) 0); }
.pc-ring::before { content: ""; grid-area: 1 / 1; width: 76px; height: 76px; border-radius: 50%; background: var(--lg-glass-strong); }
.pc-ring span { grid-area: 1 / 1; position: relative; font-size: 17px; font-weight: 650; font-variant-numeric: tabular-nums; }
.pc-ring.pc-ok { --pc-tone: var(--lg-ok); } .pc-ring.pc-warn { --pc-tone: var(--lg-warn); } .pc-ring.pc-bad { --pc-tone: var(--lg-bad); }
button.pc-kpi { font: inherit; color: inherit; text-align: left; border: 0; cursor: pointer; width: 100%; }
button.pc-kpi[aria-pressed="true"] { box-shadow: var(--lg-shadow), 0 0 0 2px var(--lg-accent); }
.pc-kpi .lg-kpi-value.pc-ok { color: var(--lg-ok-text); } .pc-kpi .lg-kpi-value.pc-bad { color: var(--lg-bad-text); }
.pc-kpi .lg-kpi-value.pc-warn { color: var(--lg-warn-text); }
.pc-sys dd { margin: 0; word-break: break-word; }
.pc-sys dt { margin: 0 0 var(--lg-space-xxs); }
.pc-toolbar { display: flex; flex-wrap: wrap; gap: var(--lg-space-s); align-items: center; }
.pc-toolbar .pc-grow { flex: 1 1 220px; position: relative; }
.pc-toolbar .pc-grow .lg-icon { position: absolute; left: 9px; top: 50%; transform: translateY(-50%); color: var(--lg-muted); pointer-events: none; }
.pc-toolbar .pc-grow .lg-input { padding-left: 30px; }
.pc-toolbar select.lg-input { width: auto; max-width: 280px; }
.pc-table { table-layout: fixed; }
.pc-table td { vertical-align: top; height: auto; padding-top: 8px; padding-bottom: 8px; overflow-wrap: anywhere; }
.pc-table th:nth-child(1) { width: 21%; } .pc-table th:nth-child(2) { width: 84px; } .pc-table th:nth-child(3) { width: 118px; }
.pc-table th:nth-child(4) { width: 24%; } .pc-table th:nth-child(5) { width: 18%; }
.pc-sub { display: block; margin-top: 2px; }
.pc-mv + .pc-mv { margin-top: var(--lg-space-s); }
.pc-mv .lg-label { display: block; margin: 0 0 2px; font-size: 10px; }
.pc-fw { display: flex; flex-wrap: wrap; gap: 4px; }
.pc-fw-chip { display: inline-block; font-size: 10.5px; border-radius: 8px; } .pc-fw-chip b { color: var(--lg-text); font-weight: 600; }
.pc-table td .lg-chip:not(.pc-fw-chip) { white-space: nowrap; }
.pc-remed { color: var(--lg-muted); }
.pc-tip { font: inherit; color: inherit; background: none; border: 0; padding: 0; cursor: help; text-align: left;
          text-decoration: underline dotted color-mix(in srgb, var(--lg-accent) 70%, transparent); text-underline-offset: 3px; }
.pc-tip .lg-icon { color: var(--lg-accent); margin-left: 4px; }
.pc-pop { position: fixed; z-index: 50; max-width: min(440px, calc(100vw - 24px)); max-height: 55vh; overflow: auto; padding: var(--lg-space-m);
          white-space: pre-line; font-size: var(--lg-fs-small); line-height: 1.55; background: var(--lg-glass-strong);
          overscroll-behavior: contain; overflow-wrap: anywhere; }
.pc-sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
.pc-empty-row td { text-align: center; color: var(--lg-muted); padding: var(--lg-space-xl); }
footer.pc-foot { text-align: center; padding: var(--lg-space-s) 0 var(--lg-space-l); }
/* Inventory tables (processes, services, network, firewall rules) */
#inventory { scroll-margin-top: var(--lg-space-m); }
.pc-inv-tabs { flex-wrap: wrap; }
.pc-inv-flags { display: flex; flex-wrap: wrap; gap: 4px; }
.pc-inv-flag { font: inherit; font-size: var(--lg-fs-small); cursor: pointer; border-radius: 999px; padding: 1px 9px;
               border: 1px solid var(--lg-line-2); background: transparent; color: var(--lg-muted); }
.pc-inv-flag[aria-pressed="true"] { border-color: color-mix(in srgb, var(--lg-accent) 45%, transparent); color: var(--lg-text);
                                    background: color-mix(in srgb, var(--lg-accent) 14%, transparent); }
.pc-inv-flag.pc-bad { color: var(--lg-bad-text); } .pc-inv-flag.pc-warn { color: var(--lg-warn-text); }
.pc-inv-table { font-size: var(--lg-fs-small); }
.pc-inv-table th { white-space: nowrap; }
.pc-inv-table th button { font: inherit; color: inherit; letter-spacing: inherit; text-transform: inherit; background: none; border: 0;
                          padding: 0; cursor: pointer; display: inline-flex; align-items: center; gap: 3px; }
.pc-inv-table th[aria-sort] button { color: var(--lg-text); }
.pc-inv-table td { max-width: 34ch; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; vertical-align: top; }
.pc-inv-table td.pc-num { text-align: right; font-variant-numeric: tabular-nums; }
.pc-inv-table td.pc-path { font-family: var(--lg-font-mono, ui-monospace, SFMono-Regular, Menlo, monospace); font-size: 11.5px; }
.pc-inv-table td.pc-inv-wrap { white-space: normal; overflow: visible; }
.pc-inv-table .lg-chip { font-size: 10.5px; margin: 0 3px 2px 0; }
.pc-inv-ref { font: inherit; color: var(--lg-accent); background: none; border: 0; padding: 0; cursor: pointer; text-decoration: underline; }
.pc-inv-ref + .pc-inv-ref::before { content: ", "; color: var(--lg-muted); text-decoration: none; display: inline-block; white-space: pre; }
.pc-inv-row { cursor: pointer; }
.pc-inv-row[aria-expanded="true"] { background: color-mix(in srgb, var(--lg-accent) 8%, transparent); }
.pc-inv-detail td { max-width: none; white-space: normal; background: color-mix(in srgb, var(--lg-text) 3%, transparent); }
.pc-inv-detail dl { display: grid; grid-template-columns: minmax(110px, max-content) 1fr; gap: 4px 14px; margin: 4px 0; }
.pc-inv-detail dt { color: var(--lg-muted); } .pc-inv-detail dd { margin: 0; overflow-wrap: anywhere; white-space: pre-wrap; }
.pc-inv-foot { display: flex; justify-content: space-between; align-items: center; gap: var(--lg-space-s); flex-wrap: wrap; }
[hidden] { display: none !important; }
@media (max-width: 760px) {
  .pc-domains, .pc-domains-label { display: none !important; }
  .pc-table { table-layout: auto; }
  .pc-table thead { display: none; }
  .pc-table, .pc-table tbody, .pc-table tr, .pc-table td { display: block; width: 100%; }
  .pc-table tr { padding: var(--lg-space-s) 0; border-bottom: 1px solid var(--lg-line); }
  .pc-table td { border: 0; padding: 3px 0; }
  .pc-table td::before { content: attr(data-label); display: block; font-size: 10px; font-weight: 600; letter-spacing: .07em;
                         text-transform: uppercase; color: var(--lg-muted); }
  .pc-table td:first-child::before { display: none; }
}
@media print {
  .lg-sidebar, .pc-toolbar, .pc-theme, .pc-inv-flags, #invMore { display: none !important; }
  .lg-app { grid-template-columns: minmax(0, 1fr); }
  .finding-row[hidden] { display: table-row !important; }
}
</style>
</head>
<body class="lg lg-backdrop">
{{LADA_SPRITE}}
<div class="lg-app">
  <nav class="lg-sidebar" aria-label="Report sections">
    <div class="lg-brand"><span class="lg-mark"><svg class="lg-icon" aria-hidden="true"><use href="#shield"/></svg></span>PostureCheck</div>
    <div class="lg-nav">
      <a href="#sec-overview"><svg class="lg-icon" aria-hidden="true"><use href="#overview"/></svg>Overview</a>
      <a href="#system"><svg class="lg-icon" aria-hidden="true"><use href="#app"/></svg>System</a>
      <a href="#findings"><svg class="lg-icon" aria-hidden="true"><use href="#list"/></svg>Findings</a>
      <a href="#inventory" id="navInventory"><svg class="lg-icon" aria-hidden="true"><use href="#layers"/></svg>Inventory</a>
    </div>
    <p class="lg-label pc-domains-label" style="margin-top: var(--lg-space-m); padding-left: var(--lg-space-s);">Domains</p>
    <div class="lg-nav pc-domains">
{{DOMAIN_NAV}}
    </div>
  </nav>
  <main class="lg-main">
    <header class="lg-header lg-enter">
      <div>
        <h1 class="lg-title">{{COMPUTERNAME}}</h1>
        <p class="lg-muted lg-small" style="margin: 0;">macOS security posture audit &middot; {{OSINFO}} &middot; generated {{TIMESTAMP}} &middot; v{{VERSION}}</p>
      </div>
      <div class="lg-row pc-theme">
        <div class="lg-tabs" role="tablist" aria-label="Theme">
          <button type="button" class="lg-tab" role="tab" aria-selected="true" data-theme-set="system">System</button>
          <button type="button" class="lg-tab" role="tab" aria-selected="false" data-theme-set="dark">Dark</button>
          <button type="button" class="lg-tab" role="tab" aria-selected="false" data-theme-set="light">Light</button>
        </div>
        <button type="button" class="lg-btn" id="printBtn"><svg class="lg-icon" aria-hidden="true"><use href="#download"/></svg>Print / PDF</button>
      </div>
    </header>

    <section id="sec-overview" class="lg-grid" style="--lg-col: 150px;" aria-label="Overview">
      <div class="lg-card pc-score pc-span2">
        <div class="pc-ring pc-{{RISK_TONE}}" style="--pc-deg: {{SCORE_DEG}};" role="img" aria-label="Compliance score {{SCORE}} percent"><span>{{SCORE}}%</span></div>
        <div>
          <p class="lg-label">Compliance score</p>
          <span class="lg-chip lg-{{RISK_TONE}}">Risk: {{RISK_LEVEL}}</span>
          <p class="lg-muted lg-small" style="margin: var(--lg-space-s) 0 0;">Weighted by severity; WARN counts half, INFO is not scored.</p>
        </div>
      </div>
      <button type="button" class="lg-card lg-kpi lg-hover pc-kpi" data-filter="all" aria-pressed="true"><p class="lg-label">Controls</p><div class="lg-kpi-value">{{TOTAL}}</div></button>
      <button type="button" class="lg-card lg-kpi lg-hover pc-kpi" data-filter="fail" aria-pressed="false"><p class="lg-label">Fail</p><div class="lg-kpi-value pc-bad">{{FAIL_COUNT}}</div></button>
      <button type="button" class="lg-card lg-kpi lg-hover pc-kpi" data-filter="warn" aria-pressed="false"><p class="lg-label">Warn</p><div class="lg-kpi-value pc-warn">{{WARN_COUNT}}</div></button>
      <button type="button" class="lg-card lg-kpi lg-hover pc-kpi" data-filter="pass" aria-pressed="false"><p class="lg-label">Pass</p><div class="lg-kpi-value pc-ok">{{PASS_COUNT}}</div></button>
      <button type="button" class="lg-card lg-kpi lg-hover pc-kpi" data-filter="info" aria-pressed="false"><p class="lg-label">Info</p><div class="lg-kpi-value">{{INFO_COUNT}}</div></button>
    </section>

    <section id="system" class="lg-card" aria-labelledby="h-system">
      <h2 class="lg-label" id="h-system">System overview</h2>
      <dl class="lg-grid pc-sys" style="--lg-col: 180px; margin: 0;">
        <div><dt class="lg-label">Model / chip</dt><dd>{{SYS_MODEL}} &middot; {{SYS_CHIP}}</dd></div>
        <div><dt class="lg-label">Memory</dt><dd>{{SYS_RAM}}</dd></div>
        <div><dt class="lg-label">Uptime</dt><dd>{{SYS_UPTIME}}</dd></div>
        <div><dt class="lg-label">Last boot</dt><dd>{{SYS_LASTBOOT}}</dd></div>
        <div><dt class="lg-label">Console user</dt><dd>{{SYS_CURRENTUSER}}</dd></div>
        <div><dt class="lg-label">IP address</dt><dd>{{SYS_IP}}</dd></div>
        <div><dt class="lg-label">Disk (root volume)</dt><dd>{{SYS_DISK}}</dd></div>
        <div><dt class="lg-label">Applications</dt><dd>{{SYS_APPCOUNT}}</dd></div>
        <div><dt class="lg-label">FileVault</dt><dd>{{SYS_FILEVAULT}}</dd></div>
        <div><dt class="lg-label">System Integrity Protection</dt><dd>{{SYS_SIP}}</dd></div>
        <div><dt class="lg-label">MDM enrollment</dt><dd>{{SYS_MDM}}</dd></div>
      </dl>
    </section>

    <section id="findings" class="lg-card lg-stack" aria-labelledby="h-findings">
      <div class="lg-header">
        <div class="lg-row">
          <h2 class="lg-label" id="h-findings" style="margin: 0;">Findings</h2>
          <button type="button" class="pc-filter-chip" id="domainChip" hidden aria-label="Clear domain filter"><span id="domainChipText"></span><svg class="lg-icon" aria-hidden="true"><use href="#x"/></svg></button>
        </div>
        <span class="lg-muted lg-small" id="resultCount" aria-live="polite"></span>
      </div>
      <div class="pc-toolbar">
        <div class="lg-tabs" role="tablist" aria-label="Status filter">
          <button type="button" class="lg-tab" role="tab" aria-selected="true" data-filter="all">All</button>
          <button type="button" class="lg-tab" role="tab" aria-selected="false" data-filter="fail">Failures</button>
          <button type="button" class="lg-tab" role="tab" aria-selected="false" data-filter="warn">Warnings</button>
          <button type="button" class="lg-tab" role="tab" aria-selected="false" data-filter="crithigh">Critical / High</button>
        </div>
        <select class="lg-input" id="categoryFilter" aria-label="Domain"><option value="">All domains</option>{{CATEGORY_OPTIONS}}</select>
        <label class="pc-grow"><span class="pc-sr">Search</span><svg class="lg-icon" aria-hidden="true"><use href="#search"/></svg>
          <input type="search" class="lg-input" id="searchInput" placeholder="Search controls, values, remediation"></label>
      </div>
      <div class="lg-table-wrap">
        <table class="lg-table pc-table">
          <thead><tr><th scope="col">Control</th><th scope="col">Status</th><th scope="col">Severity</th><th scope="col">Measured / expected</th><th scope="col">Frameworks</th><th scope="col">Remediation</th></tr></thead>
          <tbody id="findingsBody">
{{TABLE_ROWS}}
            <tr class="pc-empty-row" id="emptyRow" hidden><td colspan="6">No findings match these filters.</td></tr>
          </tbody>
        </table>
      </div>
    </section>
    <section id="inventory" class="lg-card lg-stack" aria-labelledby="h-inventory" hidden>
      <div class="lg-header">
        <div class="lg-row">
          <h2 class="lg-label" id="h-inventory" style="margin: 0;">Inventory</h2>
          <button type="button" class="pc-filter-chip" id="invColChip" hidden aria-label="Clear link filter"><span id="invColChipText"></span><svg class="lg-icon" aria-hidden="true"><use href="#x"/></svg></button>
        </div>
        <span class="lg-muted lg-small" id="invCount" aria-live="polite"></span>
      </div>
      <div class="lg-tabs pc-inv-tabs" role="tablist" aria-label="Inventory" id="invTabs"></div>
      <p class="lg-muted lg-small" id="invNote" style="margin: 0;"></p>
      <div class="pc-toolbar">
        <label class="pc-grow"><span class="pc-sr">Search inventory</span><svg class="lg-icon" aria-hidden="true"><use href="#search"/></svg>
          <input type="search" class="lg-input" id="invSearch" placeholder="Search this table"></label>
        <button type="button" class="lg-btn" id="invCsv"><svg class="lg-icon" aria-hidden="true"><use href="#download"/></svg>CSV</button>
      </div>
      <div class="pc-inv-flags" id="invFlags" aria-label="Filter by tag"></div>
      <div class="lg-table-wrap">
        <table class="lg-table pc-inv-table">
          <thead><tr id="invHead"></tr></thead>
          <tbody id="invBody"></tbody>
        </table>
      </div>
      <div class="pc-inv-foot"><span class="lg-muted lg-small">Click a row for every field; linked values open the matching rows in another table.</span>
        <button type="button" class="lg-btn" id="invMore" hidden>Show more</button></div>
      <script type="application/json" id="inventoryData">{{INVENTORY_JSON}}</script>
    </section>
    <footer class="pc-foot lg-muted lg-small">EndpointPostureCheck for macOS &middot; read-only audit, no system changes made &middot; Låda Glass {{LADA_VERSION}}</footer>
  </main>
</div>
<div class="lg-glass pc-pop" id="tipPop" role="tooltip" hidden></div>
<script>
(function () {
  var doc = document, root = doc.documentElement;
  var all = function (sel) { return Array.prototype.slice.call(doc.querySelectorAll(sel)); };
  var rows = all('.finding-row');
  var state = { status: 'all', category: '', search: '' };

  function matches(row) {
    var s = row.getAttribute('data-status'), sev = row.getAttribute('data-severity');
    var ok = state.status === 'all' ||
      (state.status === 'fail' && s === 'FAIL') || (state.status === 'warn' && s === 'WARN') ||
      (state.status === 'pass' && s === 'PASS') || (state.status === 'info' && s === 'INFO') ||
      (state.status === 'crithigh' && (s === 'FAIL' || s === 'WARN') && (sev === 'Critical' || sev === 'High'));
    return ok && (state.category === '' || row.getAttribute('data-category') === state.category) &&
      (state.search === '' || row.getAttribute('data-search').indexOf(state.search) !== -1);
  }
  function apply() {
    var shown = 0;
    rows.forEach(function (r) { var m = matches(r); r.hidden = !m; if (m) shown++; });
    doc.getElementById('emptyRow').hidden = shown !== 0;
    doc.getElementById('resultCount').textContent = shown + ' of ' + rows.length + ' controls';
    all('[data-filter]').forEach(function (b) {
      var on = b.getAttribute('data-filter') === state.status;
      b.setAttribute(b.classList.contains('pc-kpi') ? 'aria-pressed' : 'aria-selected', on ? 'true' : 'false');
    });
    all('.pc-domains a').forEach(function (a) {
      if (a.getAttribute('data-category') === state.category && state.category) a.setAttribute('aria-current', 'page');
      else a.removeAttribute('aria-current');
    });
    doc.getElementById('categoryFilter').value = state.category;
    doc.getElementById('domainChip').hidden = !state.category;
    doc.getElementById('domainChipText').textContent = state.category ? 'Domain: ' + state.category : '';
  }
  // Bring the findings into view only when they are off screen, so a filter
  // click never yanks the page around while the table is already visible.
  function revealFindings() {
    var top = doc.getElementById('findings').getBoundingClientRect().top;
    if (top < 0 || top > window.innerHeight * 0.5) doc.getElementById('findings').scrollIntoView({ block: 'start' });
  }
  all('[data-filter]').forEach(function (b) {
    b.addEventListener('click', function () {
      state.status = b.getAttribute('data-filter'); apply();
      if (b.classList.contains('pc-kpi')) revealFindings();
    });
  });
  all('.pc-domains a').forEach(function (a) {
    a.addEventListener('click', function (e) {
      e.preventDefault();   // no "#findings" jump: filter in place, scroll only if needed
      var c = a.getAttribute('data-category');
      state.category = state.category === c ? '' : c; apply();
      if (state.category) revealFindings();
    });
  });
  doc.getElementById('domainChip').addEventListener('click', function () { state.category = ''; apply(); });

  // Section links show where you are (Overview / System / Findings).
  var sectionLinks = all('.lg-nav:not(.pc-domains) a');
  // The current section is the last one whose top has scrolled up to the top
  // edge (the first section wins at the very top of the page).
  // Note: "sec-overview", not "overview", which is a sprite symbol id.
  var sectionIds = ['sec-overview', 'system', 'findings', 'inventory'], spyQueued = false;
  function spy() {
    spyQueued = false;
    var line = 80, current = sectionIds[0];
    sectionIds.forEach(function (id) { var e = doc.getElementById(id); if (e && !e.hidden && e.getBoundingClientRect().top <= line) current = id; });
    sectionLinks.forEach(function (l) {
      if (l.getAttribute('href') === '#' + current) l.setAttribute('aria-current', 'location'); else l.removeAttribute('aria-current');
    });
  }
  function queueSpy() { if (!spyQueued) { spyQueued = true; window.requestAnimationFrame(spy); } }
  window.addEventListener('scroll', queueSpy, { passive: true });
  window.addEventListener('resize', queueSpy);
  spy();
  doc.getElementById('categoryFilter').addEventListener('change', function (e) { state.category = e.target.value; apply(); });
  doc.getElementById('searchInput').addEventListener('input', function (e) { state.search = e.target.value.toLowerCase().trim(); apply(); });
  doc.getElementById('printBtn').addEventListener('click', function () { window.print(); });

  // Theme: follows the system unless the viewer picks one (remembered when storage is available).
  function setTheme(t) {
    if (t === 'dark' || t === 'light') root.setAttribute('data-theme', t); else root.removeAttribute('data-theme');
    all('[data-theme-set]').forEach(function (b) { b.setAttribute('aria-selected', b.getAttribute('data-theme-set') === (t || 'system') ? 'true' : 'false'); });
    try { localStorage.setItem('pc-theme', t || 'system'); } catch (e) { /* storage unavailable: theme still applies */ }
  }
  var saved = 'system';
  try { saved = localStorage.getItem('pc-theme') || 'system'; } catch (e) { saved = 'system'; }
  setTheme(saved);
  all('[data-theme-set]').forEach(function (b) { b.addEventListener('click', function () { setTheme(b.getAttribute('data-theme-set')); }); });

  // Item-list popover: hover, keyboard focus or click; Escape closes it. The pointer can
  // move from the button into the popover (to scroll a long list) without closing it.
  var pop = doc.getElementById('tipPop'), owner = null, hideTimer = null, overPop = false;
  function show(btn) {
    clearTimeout(hideTimer);
    if (owner && owner !== btn) owner.removeAttribute('aria-describedby');
    owner = btn; pop.textContent = btn.getAttribute('data-tip'); pop.hidden = false; pop.scrollTop = 0;
    var r = btn.getBoundingClientRect(), w = pop.offsetWidth, h = pop.offsetHeight;
    var left = Math.min(Math.max(12, r.left), window.innerWidth - w - 12);
    var top = r.bottom + 8 + h > window.innerHeight ? Math.max(12, r.top - h - 8) : r.bottom + 8;
    pop.style.left = left + 'px'; pop.style.top = top + 'px';
    btn.setAttribute('aria-describedby', 'tipPop');
  }
  function hide() { clearTimeout(hideTimer); if (owner) owner.removeAttribute('aria-describedby'); owner = null; pop.hidden = true; }
  function hideSoon() { clearTimeout(hideTimer); hideTimer = setTimeout(function () { if (!overPop && doc.activeElement !== owner) hide(); }, 250); }
  all('.pc-tip').forEach(function (b) {
    b.addEventListener('mouseenter', function () { show(b); });
    b.addEventListener('focus', function () { show(b); });
    b.addEventListener('click', function () { show(b); });   // hover/focus already opened it; a click must not close it
    b.addEventListener('mouseleave', hideSoon);
    b.addEventListener('blur', function () { if (!overPop) hide(); });
  });
  pop.addEventListener('mouseenter', function () { overPop = true; clearTimeout(hideTimer); });
  pop.addEventListener('mouseleave', function () { overPop = false; hideSoon(); });
  doc.addEventListener('keydown', function (e) { if (e.key === 'Escape') hide(); });
  window.addEventListener('scroll', function () { if (!overPop) hide(); }, { passive: true });

  apply();
})();
// Inventory tables. Data comes from the embedded JSON and is rendered with textContent only.
(function () {
  var doc = document;
  var section = doc.getElementById('inventory'), navLink = doc.getElementById('navInventory');
  var data = null;
  try { data = JSON.parse(doc.getElementById('inventoryData').textContent); } catch (e) { data = null; }
  var tables = (data && data.tables ? data.tables : []).filter(function (t) { return t && t.columns && t.rows; });
  if (!tables.length) { if (navLink) navLink.hidden = true; return; }
  section.hidden = false;
  var $ = function (id) { return doc.getElementById(id); };
  var tabsEl = $('invTabs'), noteEl = $('invNote'), headEl = $('invHead'), bodyEl = $('invBody'), countEl = $('invCount'),
      searchEl = $('invSearch'), flagsEl = $('invFlags'), moreBtn = $('invMore'), colChip = $('invColChip');
  var PAGE = 200;
  var st = { t: 0, q: '', flags: [], sort: -1, dir: 1, limit: PAGE, link: null };
  function el(tag, cls, text) { var e = doc.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }
  function cur() { return tables[st.t]; }
  function colIndex(t, label) { for (var i = 0; i < t.columns.length; i++) if (t.columns[i].label === label) return i; return -1; }
  function typeIndex(t, type) { for (var i = 0; i < t.columns.length; i++) if (t.columns[i].type === type) return i; return -1; }
  function splitList(v) { return String(v == null ? '' : v).split(',').map(function (s) { return s.trim(); }).filter(Boolean); }
  function flagTone(f) { var c = f.charAt(f.length - 1); return c === '!' ? 'bad' : c === '?' ? 'warn' : ''; }
  function flagText(f) { return /[!?]$/.test(f) ? f.slice(0, -1) : f; }
  function searchText(r) { if (r._s == null) r._s = r.join(' \u0001 ').toLowerCase(); return r._s; }
  function rowMatches(t, r, fi) {
    if (st.link && String(r[st.link.i]) !== st.link.v) return false;
    if (st.flags.length) { var have = splitList(r[fi]); for (var k = 0; k < st.flags.length; k++) if (have.indexOf(st.flags[k]) < 0) return false; }
    return !st.q || searchText(r).indexOf(st.q) >= 0;
  }
  function filtered() {
    var t = cur(), fi = typeIndex(t, 'flags'), out = t.rows.filter(function (r) { return rowMatches(t, r, fi); });
    if (st.sort >= 0) {
      var i = st.sort, num = t.columns[i].type === 'num';
      out.sort(function (a, b) {
        if (num) { var x = parseFloat(a[i]), y = parseFloat(b[i]); x = isNaN(x) ? -Infinity : x; y = isNaN(y) ? -Infinity : y; return (x - y) * st.dir; }
        return String(a[i]).localeCompare(String(b[i]), undefined, { numeric: true, sensitivity: 'base' }) * st.dir;
      });
    }
    return out;
  }
  function openLink(ref, value) {
    var dot = ref.indexOf('.'), id = ref.slice(0, dot), label = ref.slice(dot + 1);
    for (var n = 0; n < tables.length; n++) {
      if (tables[n].id !== id) continue;
      var ci = colIndex(tables[n], label); if (ci < 0) return;
      st = { t: n, q: '', flags: [], sort: -1, dir: 1, limit: PAGE, link: { i: ci, v: value, label: label } };
      searchEl.value = ''; render();
      var top = section.getBoundingClientRect().top; if (top < 0 || top > window.innerHeight * 0.5) section.scrollIntoView({ block: 'start' });
      return;
    }
  }
  function cell(t, ci, v) {
    var c = t.columns[ci], td = el('td');
    td.setAttribute('data-label', c.label);
    if (c.type === 'num') td.className = 'pc-num';
    if (c.type === 'path') td.className = 'pc-path';
    if (c.type === 'flags') {
      td.className = 'pc-inv-wrap';
      splitList(v).forEach(function (f) { var tone = flagTone(f); td.appendChild(el('span', 'lg-chip lg-plain' + (tone ? ' lg-' + tone : ''), flagText(f))); });
      return td;
    }
    if (c.type === 'ref' && c.ref && v) {
      td.className = 'pc-inv-wrap';
      String(v).split(', ').forEach(function (part) {
        if (!part) return;
        var b = el('button', 'pc-inv-ref', part); b.type = 'button';
        b.addEventListener('click', function (e) { e.stopPropagation(); openLink(c.ref, part); });
        td.appendChild(b);
      });
      return td;
    }
    td.textContent = v == null ? '' : v; td.title = td.textContent;
    return td;
  }
  function toggleDetail(tr, t, r) {
    var next = tr.nextSibling;
    if (next && next.className === 'pc-inv-detail') { bodyEl.removeChild(next); tr.setAttribute('aria-expanded', 'false'); return; }
    var d = el('tr', 'pc-inv-detail'), td = el('td'), dl = el('dl');
    td.colSpan = t.columns.length;
    t.columns.forEach(function (c, i) { if (r[i] === '' || r[i] == null) return; dl.appendChild(el('dt', '', c.label)); dl.appendChild(el('dd', '', r[i])); });
    td.appendChild(dl); d.appendChild(td); bodyEl.insertBefore(d, tr.nextSibling); tr.setAttribute('aria-expanded', 'true');
  }
  function renderTabs() {
    tabsEl.textContent = '';
    tables.forEach(function (t, n) {
      var b = el('button', 'lg-tab', t.title + ' (' + t.rows.length + ')'); b.type = 'button';
      b.setAttribute('role', 'tab'); b.setAttribute('aria-selected', n === st.t ? 'true' : 'false');
      b.addEventListener('click', function () { st = { t: n, q: '', flags: [], sort: -1, dir: 1, limit: PAGE, link: null }; searchEl.value = ''; render(); });
      tabsEl.appendChild(b);
    });
  }
  function renderFlags(t) {
    flagsEl.textContent = '';
    var fi = typeIndex(t, 'flags'); if (fi < 0) { flagsEl.hidden = true; return; }
    var counts = {}, order = [];
    t.rows.forEach(function (r) { splitList(r[fi]).forEach(function (f) { if (!counts[f]) { counts[f] = 0; order.push(f); } counts[f]++; }); });
    order.sort(function (a, b) { var ta = flagTone(a) ? 0 : 1, tb = flagTone(b) ? 0 : 1; return ta - tb || counts[b] - counts[a]; });
    flagsEl.hidden = !order.length;
    order.forEach(function (f) {
      var tone = flagTone(f), b = el('button', 'pc-inv-flag' + (tone ? ' pc-' + tone : ''), flagText(f) + ' ' + counts[f]); b.type = 'button';
      b.setAttribute('aria-pressed', st.flags.indexOf(f) >= 0 ? 'true' : 'false');
      b.addEventListener('click', function () { var k = st.flags.indexOf(f); if (k >= 0) st.flags.splice(k, 1); else st.flags.push(f); st.limit = PAGE; render(); });
      flagsEl.appendChild(b);
    });
  }
  function render() {
    var t = cur(), rows = filtered();
    renderTabs(); renderFlags(t);
    noteEl.textContent = t.note || ''; noteEl.hidden = !t.note;
    headEl.textContent = '';
    t.columns.forEach(function (c, i) {
      var th = el('th'), b = el('button', '', c.label); th.scope = 'col'; b.type = 'button';
      if (st.sort === i) th.setAttribute('aria-sort', st.dir > 0 ? 'ascending' : 'descending');
      b.appendChild(el('span', 'lg-muted', st.sort === i ? (st.dir > 0 ? '\u25B2' : '\u25BC') : ''));
      b.addEventListener('click', function () { if (st.sort === i) st.dir = -st.dir; else { st.sort = i; st.dir = c.type === 'num' ? -1 : 1; } render(); });
      th.appendChild(b); headEl.appendChild(th);
    });
    bodyEl.textContent = '';
    rows.slice(0, st.limit).forEach(function (r) {
      var tr = el('tr', 'pc-inv-row'); tr.tabIndex = 0; tr.setAttribute('aria-expanded', 'false');
      for (var i = 0; i < t.columns.length; i++) tr.appendChild(cell(t, i, r[i]));
      tr.addEventListener('click', function () { toggleDetail(tr, t, r); });
      tr.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggleDetail(tr, t, r); } });
      bodyEl.appendChild(tr);
    });
    if (!rows.length) { var tr = el('tr', 'pc-empty-row'), td = el('td', '', 'No rows match.'); td.colSpan = t.columns.length; tr.appendChild(td); bodyEl.appendChild(tr); }
    moreBtn.hidden = rows.length <= st.limit;
    countEl.textContent = Math.min(rows.length, st.limit) + ' shown, ' + rows.length + ' match, ' + t.rows.length + ' total';
    colChip.hidden = !st.link;
    $('invColChipText').textContent = st.link ? st.link.label + ' = ' + st.link.v : '';
  }
  searchEl.addEventListener('input', function () { st.q = searchEl.value.toLowerCase().trim(); st.limit = PAGE; render(); });
  moreBtn.addEventListener('click', function () { st.limit += PAGE * 5; render(); });
  colChip.addEventListener('click', function () { st.link = null; render(); });
  $('invCsv').addEventListener('click', function () {
    var t = cur();
    var q = function (v) { v = String(v == null ? '' : v); if (/^[=+\-@\t\r]/.test(v)) v = "'" + v; return '"' + v.replace(/"/g, '""') + '"'; };
    var lines = [t.columns.map(function (c) { return q(c.label); }).join(',')];
    filtered().forEach(function (r) { lines.push(t.columns.map(function (c, i) { return q(r[i]); }).join(',')); });
    var a = el('a'); a.href = URL.createObjectURL(new Blob([lines.join('\r\n')], { type: 'text/csv' })); a.download = t.id + '.csv';
    doc.body.appendChild(a); a.click(); doc.body.removeChild(a); setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
  });
  render();
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
    local risk_tone="ok"
    case "$POSTURE_RISK" in
        CRITICAL|HIGH) risk_tone="bad" ;;
        MEDIUM) risk_tone="warn" ;;
    esac

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

    local table_rows domain_nav
    table_rows=$(_findings_table_rows)
    domain_nav=$(_domain_nav_links)

    local html
    html=$(get_html_template)

    # Design-system assets are generated into the build by build.sh; when a
    # module is sourced on its own (tests), the page still renders unstyled.
    html_set_token html '{{LADA_CSS}}' "${LADA_GLASS_CSS:-}"
    html_set_token html '{{LADA_SPRITE}}' "${LADA_GLASS_SPRITE:-}"
    html_set_token html '{{LADA_VERSION}}' "${LADA_GLASS_VERSION:-}"
    html_set_token html '{{COMPUTERNAME}}' "$(html_escape "$SYS_COMPUTERNAME")"
    html_set_token html '{{OSINFO}}' "$(html_escape "${SYS_OSVERSION:-Unknown}")"
    html_set_token html '{{TIMESTAMP}}' "$(date '+%Y-%m-%d %H:%M:%S')"
    html_set_token html '{{VERSION}}' "$SCRIPT_VERSION"
    html_set_token html '{{SCORE}}' "$POSTURE_SCORE"
    html_set_token html '{{SCORE_DEG}}' "$score_deg"
    html_set_token html '{{RISK_LEVEL}}' "$POSTURE_RISK"
    html_set_token html '{{RISK_TONE}}' "$risk_tone"
    html_set_token html '{{TOTAL}}' "$POSTURE_TOTAL"
    html_set_token html '{{PASS_COUNT}}' "$POSTURE_PASS"
    html_set_token html '{{FAIL_COUNT}}' "$POSTURE_FAIL"
    html_set_token html '{{WARN_COUNT}}' "$POSTURE_WARN"
    html_set_token html '{{INFO_COUNT}}' "$POSTURE_INFO"
    html_set_token html '{{CATEGORY_OPTIONS}}' "$category_options"
    html_set_token html '{{DOMAIN_NAV}}' "$domain_nav"
    html_set_token html '{{TABLE_ROWS}}' "$table_rows"
    html_set_token html '{{SYS_MODEL}}' "$(html_escape "$SYS_MODEL")"
    html_set_token html '{{SYS_CHIP}}' "$(html_escape "$SYS_CHIP")"
    html_set_token html '{{SYS_RAM}}' "$(html_escape "$SYS_RAM")"
    html_set_token html '{{SYS_UPTIME}}' "$(html_escape "$SYS_UPTIME")"
    html_set_token html '{{SYS_LASTBOOT}}' "$(html_escape "$SYS_LASTBOOT")"
    html_set_token html '{{SYS_CURRENTUSER}}' "$(html_escape "$SYS_CURRENTUSER")"
    html_set_token html '{{SYS_IP}}' "$(html_escape "$SYS_IP")"
    html_set_token html '{{SYS_DISK}}' "$(html_escape "$SYS_DISK")"
    html_set_token html '{{SYS_APPCOUNT}}' "$(html_escape "$SYS_APPCOUNT")"
    html_set_token html '{{SYS_FILEVAULT}}' "$(html_escape "$SYS_FILEVAULT")"
    html_set_token html '{{SYS_SIP}}' "$(html_escape "$SYS_SIP")"
    html_set_token html '{{SYS_MDM}}' "$(html_escape "$SYS_MDM")"
    # Last: collected data must never be scanned for the other tokens.
    html_set_token html '{{INVENTORY_JSON}}' "$(inventory_json)"

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
    # Every other control character (ANSI escapes and the like in command
    # output) must be \u-escaped too, or the export is not valid JSON
    # (caught by test-engine.zsh with plutil). Rare, so only then is the
    # string walked character by character.
    if [[ "$s" == *[[:cntrl:]]* ]]; then
        local out="" ch="" i
        for (( i = 1; i <= ${#s}; i++ )); do
            ch="${s[i]}"
            if [[ "$ch" == [[:cntrl:]] ]]; then
                out+=$(printf '\\u%04x' "'$ch")
            else
                out+="$ch"
            fi
        done
        s="$out"
    fi
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
  "BaselineFile": "$(json_escape "${BASELINE_PATH:-}")",
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
  "Findings": [$findings_json],
  "Inventory": $(inventory_json)
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
        system_settings_filevault_enforce)
            cat <<'EOF'
echo "FileVault needs an interactive prompt or a pre-generated institutional recovery key; it cannot be silently enabled unattended."
echo "Run interactively: sudo fdesetup enable"
EOF
            ;;
        os_root_disable)
            print -r -- "sudo dscl . -create /Users/root Password '*'"
            ;;
        system_settings_guest_account_disable)
            print -r -- 'sudo defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false'
            ;;
        system_settings_firewall_enable)
            print -r -- 'sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on'
            ;;
        os_sshd_permit_root_login_configure)
            cat <<'EOF'
sudo cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.bak.$(date +%Y%m%d%H%M%S)"
sudo sed -i '' -E 's/^#?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
echo "sshd_config updated. Restart sshd (or reboot) for the change to take effect."
EOF
            ;;
        system_settings_screensaver_password_enforce)
            # The old askForPassword defaults key has no effect on current
            # macOS, and sysadminctl -screenLock needs the user's password.
            cat <<'EOF'
echo "Turn on 'Require password after screen saver begins or display is turned off' in System Settings > Lock Screen,"
echo "or deploy a Screensaver profile payload with askForPassword=true and askForPasswordDelay=0 (see --generate-profile)."
EOF
            ;;
        system_settings_automatic_login_disable)
            print -r -- 'sudo defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser'
            ;;
        # Controls with no mSCP rule are keyed by control name (see
        # _remediation_snippet_for). Never key a snippet on "N/A".
        'control:DYLD_INSERT_LIBRARIES Global Env')
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

# Resolves the snippet for one finding: each mSCP rule ID in its
# (possibly comma-separated) mSCP field, then the control name for
# controls mSCP has no rule for. "N/A" never matches anything.
_remediation_snippet_for() {
    local mscp_field="$1" control="$2" id="" snippet=""
    for id in ${(s:,:)mscp_field}; do
        id="${id//[[:space:]]/}"
        [[ -z "$id" || "$id" == N/A ]] && continue
        snippet=$(get_remediation_snippet "$id")
        [[ -n "$snippet" ]] && { print -r -- "$snippet"; return 0; }
    done
    get_remediation_snippet "control:$control"
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
                snippet=$(_remediation_snippet_for "${AUDIT_MSCP[$idx]}" "${AUDIT_CONTROL[$idx]}")
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

# ---- 94-profile.zsh ----
#
# Hardening profile generator (--generate-profile). Turns every
# profile-enforceable setting that came out WARN or FAIL this run
# (recorded by record_profile_fix in 01-core.zsh) into one unsigned
# .mobileconfig for review and upload to an MDM. It is written to disk
# only — never installed: the auditor does not change system state.
#
# com.apple.applicationaccess keys use the native Restrictions payload;
# every other preference domain goes into a Custom Settings
# (com.apple.ManagedClient.preferences) payload, the MDM-standard way to
# force arbitrary managed preferences.

# Settings that take an integer even when the recommended value is 0/1.
typeset -ga PROFILE_INTEGER_KEYS
PROFILE_INTEGER_KEYS=(RetriesUntilHint idleTime enforcedSoftwareUpdateDelay 'Siri Data Sharing Opt-In Status'
    'Search Queries Data Sharing Status' BlockStoragePolicy WebKitStorageBlockingPolicy
    WebKitPreferences.storageBlockingPolicy)

_plist_escape() {
    local s="$1"
    s="${s//&/&amp;}"; s="${s//</&lt;}"; s="${s//>/&gt;}"
    print -r -- "$s"
}

# <key>…</key> plus a typed value element.
_plist_kv() {
    local key="$1" value="$2" indent="$3"
    print -r -- "$indent<key>$(_plist_escape "$key")</key>"
    if (( ${PROFILE_INTEGER_KEYS[(Ie)$key]} )) || [[ "$value" != [01] ]]; then
        if [[ "$value" == <-> ]]; then
            print -r -- "$indent<integer>$value</integer>"
        else
            print -r -- "$indent<string>$(_plist_escape "$value")</string>"
        fi
    elif [[ "$value" == 1 ]]; then
        print -r -- "$indent<true/>"
    else
        print -r -- "$indent<false/>"
    fi
}

_new_uuid() {
    uuidgen 2>/dev/null || print -r -- "$(date +%s)-$RANDOM-$RANDOM"
}

# Prints the profile XML for the recorded fixes; returns 1 when there are none.
render_hardening_profile() {
    local i="" suite="" key="" value="" profile_uuid=""
    local -a restriction_idx custom_suites
    (( ${#PROFILE_FIX_KEYS[@]} > 0 )) || return 1
    for (( i = 1; i <= ${#PROFILE_FIX_KEYS[@]}; i++ )); do
        if [[ "${PROFILE_FIX_SUITES[$i]}" == com.apple.applicationaccess ]]; then
            restriction_idx+=("$i")
        else
            (( ${custom_suites[(Ie)${PROFILE_FIX_SUITES[$i]}]} )) || custom_suites+=("${PROFILE_FIX_SUITES[$i]}")
        fi
    done
    profile_uuid=$(_new_uuid)

    cat <<EOH
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
EOH
    if (( ${#restriction_idx[@]} )); then
        print -r -- '        <dict>'
        print -r -- '            <key>PayloadType</key><string>com.apple.applicationaccess</string>'
        print -r -- "            <key>PayloadIdentifier</key><string>com.endpointposturecheck.hardening.restrictions</string>"
        print -r -- "            <key>PayloadUUID</key><string>$(_new_uuid)</string>"
        print -r -- '            <key>PayloadVersion</key><integer>1</integer>'
        print -r -- '            <key>PayloadDisplayName</key><string>Restrictions</string>'
        for i in "${restriction_idx[@]}"; do
            _plist_kv "${PROFILE_FIX_KEYS[$i]}" "${PROFILE_FIX_VALUES[$i]}" '            '
        done
        print -r -- '        </dict>'
    fi
    if (( ${#custom_suites[@]} )); then
        print -r -- '        <dict>'
        print -r -- '            <key>PayloadType</key><string>com.apple.ManagedClient.preferences</string>'
        print -r -- "            <key>PayloadIdentifier</key><string>com.endpointposturecheck.hardening.custom</string>"
        print -r -- "            <key>PayloadUUID</key><string>$(_new_uuid)</string>"
        print -r -- '            <key>PayloadVersion</key><integer>1</integer>'
        print -r -- '            <key>PayloadDisplayName</key><string>Custom Settings</string>'
        print -r -- '            <key>PayloadContent</key>'
        print -r -- '            <dict>'
        for suite in "${custom_suites[@]}"; do
            print -r -- "                <key>$(_plist_escape "$suite")</key>"
            print -r -- '                <dict><key>Forced</key><array><dict><key>mcx_preference_settings</key><dict>'
            for (( i = 1; i <= ${#PROFILE_FIX_KEYS[@]}; i++ )); do
                [[ "${PROFILE_FIX_SUITES[$i]}" == "$suite" ]] || continue
                _plist_kv "${PROFILE_FIX_KEYS[$i]}" "${PROFILE_FIX_VALUES[$i]}" '                    '
            done
            print -r -- '                </dict></dict></array></dict>'
        done
        print -r -- '            </dict>'
        print -r -- '        </dict>'
    fi
    cat <<EOF2
    </array>
    <key>PayloadDisplayName</key>
    <string>EndpointPostureCheck Hardening (${COMPUTER_NAME:-this Mac})</string>
    <key>PayloadDescription</key>
    <string>Generated by EndpointPostureCheck from the profile-enforceable WARN/FAIL findings of one audit run. Review every setting and test on a pilot Mac before deploying through your MDM. Unsigned.</string>
    <key>PayloadIdentifier</key>
    <string>com.endpointposturecheck.hardening.$profile_uuid</string>
    <key>PayloadUUID</key>
    <string>$profile_uuid</string>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadScope</key>
    <string>System</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>
EOF2
}

generate_hardening_profile() {
    local output_path="$1"
    if ! render_hardening_profile > "$output_path"; then
        command rm -f "$output_path"
        return 1
    fi
    chmod 644 "$output_path"
}

# ---- 95-baseline.zsh ----
#
# Baseline comparison (--baseline <previous.json>): compares this run with
# an earlier JSON export of the same tool. Drift is often a stronger
# signal than a single snapshot: a new LaunchDaemon, admin account, Full
# Disk Access grant or browser extension since last week matters even
# when each one looks plausible on its own.
#
# Two findings, added after every check has run:
#   - New Privileged & Persistence Items Since Baseline (scored, WARN):
#     items that appeared in security-relevant inventories.
#   - Posture Changes Since Baseline (INFO): controls that got worse or
#     better. Not scored, because those controls already carry their own
#     status in this run (scoring them again would double-count).

# Inventories whose new items are a security signal.
typeset -ga BASELINE_TRACKED_CONTROLS
BASELINE_TRACKED_CONTROLS=(
    'Autostart Inventory (Apps & Scripts)' 'Login Items & Background Task Inventory'
    'Admin Group Membership Inventory' 'Full Disk Access Grants' 'Screen Recording Grants' 'Accessibility Grants'
    'Browser Extensions Inventory' 'Third-Party System Extensions Inventory' 'Third-Party Kernel Extension Inventory'
    'Installed Profiles Inventory' 'Privileged Helper Tools' 'SSH Authorized Keys Inventory'
)
# Inventories that change too often to score; reported in the INFO finding.
typeset -ga BASELINE_INFO_CONTROLS
BASELINE_INFO_CONTROLS=('Listening Ports Inventory' 'Installed Applications Inventory')

# JXA: prints "@meta\x1f<ComputerName>\x1f<ScanStartTime>" then one
# "<control>\x1f<status>\x1f<details with \x1e between lines>" per finding.
typeset -g BASELINE_JXA
read -r -d '' BASELINE_JXA <<'JXA'
ObjC.import('Foundation');
function run(argv) {
    var s = $.NSString.stringWithContentsOfFileEncodingError(argv[0], $.NSUTF8StringEncoding, null);
    if (s.isNil()) throw new Error('cannot read ' + argv[0]);
    var d = JSON.parse(ObjC.unwrap(s));
    if (!d || !Array.isArray(d.Findings)) throw new Error('not an EndpointPostureCheck JSON export');
    var c = function (v) { return String(v == null ? '' : v).replace(/[\x1e\x1f\r]/g, ' '); };
    var out = ['@meta\x1f' + c(d.ComputerName) + '\x1f' + c(d.ScanStartTime)];
    d.Findings.forEach(function (f) {
        out.push([c(f.Control), c(f.Status), c(f.Details).split('\n').join('\x1e')].join('\x1f'));
    });
    return out.join('\n');
}
JXA

compare_with_baseline() {
    local baseline_path="$1" raw="" line="" control="" bstatus="" bdetails="" meta_host="" meta_time="" i=""
    local -A base_status base_details
    raw=$(osascript -l JavaScript -e "$BASELINE_JXA" "$baseline_path" 2>&1)
    if [[ $? -ne 0 || "$raw" != @meta* ]]; then
        add_audit_result --category 'Baseline Comparison' --control 'Baseline Comparison' \
            --status WARN --severity Low --current "Could not read baseline $baseline_path: ${raw[1,200]}" \
            --recommended 'A JSON export from an earlier run of this tool' --cis-macos 'N/A' --mscp 'N/A' \
            --recommendation 'Pass a file written by --export-json from a previous run.'
        return 0
    fi
    for line in "${(@f)raw}"; do
        IFS=$'\x1f' read -r control bstatus bdetails <<< "$line"
        if [[ "$control" == @meta ]]; then
            meta_host="$bstatus"; meta_time="$bdetails"; continue
        fi
        base_status[$control]="$bstatus"; base_details[$control]="$bdetails"
    done

    local -a new_items removed_items regressions improvements info_changes
    # Statuses come from the baseline file: compared through a fixed table,
    # never in an arithmetic context.
    local -A rank
    rank=(PASS 0 WARN 1 FAIL 2)
    local cur_status="" cur_details="" item="" was="" now=""
    local -a cur_list base_list
    for (( i = 1; i <= ${#AUDIT_CONTROL[@]}; i++ )); do
        control="${AUDIT_CONTROL[$i]}"; cur_status="${AUDIT_STATUS[$i]}"; cur_details="${AUDIT_DETAILS[$i]}"
        [[ -n "${base_status[$control]+x}" ]] || continue
        was="${base_status[$control]}"; now="$cur_status"
        if [[ -n "${rank[$was]:-}" && -n "${rank[$now]:-}" && "$was" != "$now" ]]; then
            if [[ "${rank[$now]}" > "${rank[$was]}" ]]; then regressions+=("$control: $was -> $now")
            else improvements+=("$control: $was -> $now"); fi
        fi
        if (( ${BASELINE_TRACKED_CONTROLS[(Ie)$control]} || ${BASELINE_INFO_CONTROLS[(Ie)$control]} )); then
            cur_list=("${(@f)cur_details}"); cur_list=(${cur_list:#})
            base_list=("${(@ps:\x1e:)base_details[$control]}"); base_list=(${base_list:#})
            for item in "${cur_list[@]}"; do
                (( ${base_list[(Ie)$item]} )) && continue
                if (( ${BASELINE_TRACKED_CONTROLS[(Ie)$control]} )); then new_items+=("+ [$control] $item")
                else info_changes+=("+ [$control] $item"); fi
            done
            for item in "${base_list[@]}"; do
                (( ${cur_list[(Ie)$item]} )) && continue
                if (( ${BASELINE_TRACKED_CONTROLS[(Ie)$control]} )); then removed_items+=("- [$control] $item")
                else info_changes+=("- [$control] $item"); fi
            done
        fi
    done

    local since="${meta_time:-unknown time}${meta_host:+ on $meta_host}"
    [[ -n "$meta_host" && "$meta_host" != "$COMPUTER_NAME" ]] && since+=" (a different computer)"
    local -a fw
    fw=(--recommended 'No unexpected new persistence, privilege or extension items since the baseline'
        --cis 'CIS 1.1, 2.1, 4.1' --nist 'CM-3, CM-8(3), SI-4' --mitre 'T1543 (Create or Modify System Process), T1098 (Account Manipulation)'
        --iso27001 'A.8.9' --nis2 'Art.21(2)(d)' --cis-macos 'N/A' --mscp 'N/A')
    if [[ ${#new_items[@]} -gt 0 ]]; then
        add_audit_result --category 'Baseline Comparison' --control 'New Privileged & Persistence Items Since Baseline' \
            --status WARN --severity Medium --current "${#new_items[@]} new item(s) since $since${removed_items:+; ${#removed_items[@]} removed}" \
            --details "${(F)new_items}${removed_items:+$NL${(F)removed_items}}" "${fw[@]}" \
            --recommendation 'Confirm each new item was an intended change (software install, admin change, granted permission). Unexplained new autostart items, admin members, Full Disk Access grants or extensions are a common sign of compromise.'
    else
        local -a removed_flag
        (( ${#removed_items[@]} )) && removed_flag=(--details "${(F)removed_items}")
        add_audit_result --category 'Baseline Comparison' --control 'New Privileged & Persistence Items Since Baseline' \
            --status PASS --severity Medium --current "No new items in ${#BASELINE_TRACKED_CONTROLS[@]} tracked inventories since $since${removed_items:+ (${#removed_items[@]} removed)}" \
            "${removed_flag[@]}" "${fw[@]}" --recommendation 'No action required.'
    fi
    local -a changes
    changes=("${regressions[@]/#/worse: }" "${improvements[@]/#/better: }" "${info_changes[@]}")
    changes=(${changes:#})
    add_audit_result --category 'Baseline Comparison' --control 'Posture Changes Since Baseline' \
        --status INFO --severity Informational \
        --current "${#regressions[@]} control(s) worse, ${#improvements[@]} better since $since" \
        --details "${(F)changes}" --recommended 'N/A' --cis-macos 'N/A' --mscp 'N/A' \
        --recommendation 'Informational. Controls that got worse are already scored in this run; review why they changed.'
    BASELINE_SUMMARY="${#new_items[@]} new tracked item(s), ${#regressions[@]} control(s) worse, ${#improvements[@]} better (baseline: $since)"
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
        PROFILE_OUTPUT_PATH="$(pwd)/EndpointPostureCheck-Hardening.mobileconfig"
    elif [[ -d "$REPORT_PATH" ]] || [[ ! -e "$REPORT_PATH" && "${REPORT_PATH:l}" != *.htm(|l) ]]; then
        # A path that does not exist yet and has no .html extension is a
        # folder to create (a run with --report-path ~/Desktop/run once
        # wrote the dashboard to an extension-less file named "run").
        mkdir -p "$REPORT_PATH"
        HTML_OUTPUT_PATH="$REPORT_PATH/$default_html_name"
        JSON_OUTPUT_PATH="$REPORT_PATH/$default_json_name"
        REMEDIATION_OUTPUT_PATH="$REPORT_PATH/Remediate-EndpointPostureCheck.sh"
        PROFILE_OUTPUT_PATH="$REPORT_PATH/EndpointPostureCheck-Hardening.mobileconfig"
    else
        HTML_OUTPUT_PATH="$REPORT_PATH"
        local parent_dir
        parent_dir=$(dirname "$REPORT_PATH")
        [[ ! -d "$parent_dir" ]] && mkdir -p "$parent_dir"
        JSON_OUTPUT_PATH="$parent_dir/$default_json_name"
        REMEDIATION_OUTPUT_PATH="$parent_dir/Remediate-EndpointPostureCheck.sh"
        PROFILE_OUTPUT_PATH="$parent_dir/EndpointPostureCheck-Hardening.mobileconfig"
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

    # Slow, independent queries run in the background while the other
    # checks execute (measured: sfltool dumpbtm 3-23s, Wi-Fi ~8s, the
    # 7-day XProtect Remediator log a few seconds).
    prefetch btm sfltool dumpbtm
    prefetch wifi system_profiler SPAirPortDataType
    prefetch xpr_log xpr_log_query

    _run_all_checks
    prefetch_cleanup

    if [[ -n "${BASELINE_PATH:-}" ]]; then
        write_section_banner 'Baseline Comparison'
        compare_with_baseline "$BASELINE_PATH"
    fi

    get_compliance_posture
    _print_audit_summary
    [[ -n "${BASELINE_SUMMARY:-}" ]] && echo "  Baseline: $BASELINE_SUMMARY" && echo ''

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

    if [[ "${GENERATE_PROFILE:-0}" -eq 1 ]]; then
        if generate_hardening_profile "$PROFILE_OUTPUT_PATH"; then
            echo "[+] Hardening profile written  : $PROFILE_OUTPUT_PATH (${#PROFILE_FIX_KEYS[@]} setting(s); review before deploying)"
        else
            echo "[=] No profile-enforceable WARN/FAIL settings; no hardening profile written."
        fi
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
    check_gatekeeper_status check_quarantine_enforcement_telemetry check_applications_quarantine_flag_survey check_download_quarantine_disabled
    # Domain 5: Malware Defense (XProtect / MRT / EDR)
    check_xprotect_freshness check_xprotect_remediator_results check_mrt_freshness check_third_party_edr_presence check_endpoint_security_clients
    # Domain 6: TCC & Privacy Controls
    check_tcc_full_disk_access_grants check_tcc_screen_recording_grants check_tcc_accessibility_grants check_tcc_grants_to_script_hosts
    check_tcc_camera_microphone_grants check_tcc_database_permissions
    check_location_services_enabled check_location_services_menu_icon
    # Domain 7: Identity, Accounts & Privilege Management
    check_root_account_disabled check_guest_account_disabled check_admin_group_membership_inventory check_password_policy_configured
    check_sudoers_configuration check_sudo_environment_and_dropins check_sudo_rules_shell_escape check_authorization_db_weakened_rights check_pam_configuration_integrity
    check_password_lockout_threshold check_password_minimum_length check_password_age check_password_history
    check_sudo_timeout_zero check_sudo_timestamp_per_tty check_sudo_logging_enabled
    check_admin_password_for_system_preferences check_admin_cannot_unlock_other_sessions
    check_user_password_hints_absent check_smb_guest_access_disabled check_guest_home_folder_absent
    # Domain 8: Network Firewall & Packet Filtering
    check_firewall_state check_firewall_stealth_mode check_firewall_block_all_incoming check_firewall_signed_app_auto_allow
    check_firewall_per_app_exceptions check_etc_hosts_integrity
    # Domain 9: Remote Access & Sharing Services
    check_screen_sharing_state check_remote_management_state check_file_sharing_state check_remote_login_toggle check_legacy_vnc_password
    check_airplay_receiver_disabled check_printer_sharing_disabled check_remote_apple_events_disabled
    check_internet_sharing_disabled check_content_caching_disabled check_media_sharing_disabled
    check_bluetooth_sharing_disabled
    # Domain 10: SSH Server & Client Hardening
    check_sshd_password_auth check_sshd_permit_root_login check_sshd_weak_ciphers check_ssh_client_strict_host_key_checking check_sshd_risky_options
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
    # Domain 16: Privilege Escalation: File & Directory Permissions
    check_writable_launchd_directories check_writable_path_directories check_suid_sgid_binary_audit
    check_home_folders_secure check_world_writable_applications check_world_writable_system_folder
    check_world_writable_library_folder
    # Domain 17: Dylib Hijacking & Code Injection
    check_dyld_insert_libraries_global_env check_writable_dylib_search_paths check_hardened_runtime_spotcheck check_electron_node_fuses check_library_validation_policy
    # Domain 18: Credential Exposure & Secret Leaks
    check_ssh_private_key_permissions check_cloud_cli_credential_files check_shell_history_secret_sweep check_sensitive_filename_sweep check_privileged_and_other_user_history_secrets
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
    check_browser_extensions_inventory check_browser_extension_risk
    # Domain 24: Ransomware Resilience & Recovery
    check_time_machine_configured_and_recent check_time_machine_encryption check_local_apfs_snapshots
    check_time_machine_auto_backup
    # Domain 25: Third-Party Software & Package Inventory
    check_installed_applications_inventory check_homebrew_prefix_permissions check_homebrew_package_inventory
    # Domain 26: System Services & Daemon Exposure
    check_listening_ports_inventory check_nonapple_running_launchd_services check_network_exposed_listeners
    check_bonjour_advertising_disabled check_http_server_disabled check_nfs_server_disabled
    # Domain 27: Kernel & Boot Security
    check_boot_security_policy check_authenticated_root_status check_nvram_boot_args check_thirdparty_kext_inventory
    # Domain 28: Virtualization & Container Escape Surface
    check_docker_desktop_presence check_vm_hypervisor_apps_inventory check_container_runtime_exposure
    # Domain 29: Data Loss Prevention & Sensitive Data
    check_screenshot_save_location_cloud_exposure check_handoff_universal_clipboard
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
