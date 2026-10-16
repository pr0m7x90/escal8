#!/usr/bin/env bash
# ============================== 00_header.sh ==============================
# ==============================================================================
# Escal8 - Linux Privilege Escalation Enumeration Tool
# ------------------------------------------------------------------------------
# Standalone, dependency-light Bash script for authorized security assessments
# (CTF, HTB/THM, pentest labs). Read-only enumeration only - this tool never
# attempts to escalate privileges, modify system state, or exploit anything.
#
# Generated from modular sources by build.sh - edit src/*.sh, not this file.
# ==============================================================================

# We require Bash itself (associative arrays, `local`, base#n arithmetic
# like $((16#ff)), [ "$x" ] tests, etc.) but deliberately avoid GNU-only
# coreutils flags throughout so the individual checks stay portable across
# BusyBox / musl / older GNU targets that a real assessment might land on.
if [ -z "${BASH_VERSION:-}" ]; then
    echo "Escal8 requires bash. Run it as: bash escal8.sh" >&2
    exit 1
fi

# Don't use 'set -e' - a single failed/absent command in a check must never
# abort the whole enumeration run. We handle errors locally per-check instead.
set -u
set -o pipefail 2>/dev/null || true

ESCAL8_VERSION="1.7.0-rc1"
ESCAL8_NAME="Escal8"
ESCAL8_START_EPOCH="$(date +%s 2>/dev/null || echo 0)"

# ============================== 01_colors.sh ==============================
# ------------------------------------------------------------------------------
# Colors / styling
# ------------------------------------------------------------------------------
# Colors are enabled only when stdout is a tty and --no-color was not given.
# All color variables default to empty strings when disabled, so every print
# statement can unconditionally reference them without branching.

ESCAL8_NO_COLOR=0

_escal8_colors_init() {
    if [ "$ESCAL8_NO_COLOR" -eq 1 ] || [ ! -t 1 ] || [ -n "${NO_COLOR:-}" ]; then
        C_RESET=""; C_BOLD=""; C_DIM=""
        C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_MAGENTA=""; C_CYAN=""; C_WHITE=""
        C_BG_RED=""
        return
    fi
    C_RESET="$(printf '\033[0m')"
    C_BOLD="$(printf '\033[1m')"
    C_DIM="$(printf '\033[2m')"
    C_RED="$(printf '\033[31m')"
    C_GREEN="$(printf '\033[32m')"
    C_YELLOW="$(printf '\033[33m')"
    C_BLUE="$(printf '\033[34m')"
    C_MAGENTA="$(printf '\033[35m')"
    C_CYAN="$(printf '\033[36m')"
    C_WHITE="$(printf '\033[37m')"
    C_BG_RED="$(printf '\033[41m')"
}

# Severity -> color mapping, used by the finding interface and the summary.
_escal8_sev_color() {
    case "$1" in
        CRITICAL) printf '%s' "${C_BG_RED}${C_WHITE}${C_BOLD}" ;;
        HIGH)     printf '%s' "${C_RED}${C_BOLD}" ;;
        MEDIUM)   printf '%s' "${C_YELLOW}${C_BOLD}" ;;
        LOW)      printf '%s' "${C_CYAN}" ;;
        INFO)     printf '%s' "${C_BLUE}" ;;
        OK)       printf '%s' "${C_GREEN}" ;;
        SKIP)     printf '%s' "${C_DIM}" ;;
        FAILED)   printf '%s' "${C_MAGENTA}${C_BOLD}" ;;
        *)        printf '%s' "${C_WHITE}" ;;
    esac
}

# ============================== 02_utils.sh ==============================
# ------------------------------------------------------------------------------
# Core utilities
# ------------------------------------------------------------------------------

ESCAL8_QUIET=0
ESCAL8_OUTFILE=""
ESCAL8_FORMAT="text"      # text | json | html
ESCAL8_TMPDIR=""

# Findings are accumulated as pipe-delimited records in a temp file so the
# final summary and JSON/HTML reports can be generated after the live run.
# Fields: SEVERITY|CHECK_ID|TITLE|DETAIL (detail has newlines encoded as \n)
ESCAL8_FINDINGS_FILE=""

# Counts per severity for the summary footer. FAILED is not a target
# vulnerability severity - it's reserved for Escal8's own internal "a check
# module exited unexpectedly" signal (see 99_main.sh), kept in the same
# table purely so the existing summary/report plumbing handles it for free.
declare -A ESCAL8_COUNTS=( [CRITICAL]=0 [HIGH]=0 [MEDIUM]=0 [LOW]=0 [INFO]=0 [OK]=0 [SKIP]=0 [FAILED]=0 )

# Per-check-module instrumentation, used to tell "completed" (actually
# assessed something) apart from "skipped" (ran, but every single thing it
# tried to look at was unavailable, so nothing was really assessed) at the
# whole-check level - see 99_main.sh's dispatch loop and
# escal8_print_check_coverage in 90_report.sh. _ESCAL8_CURRENT_CHECK is set
# by the dispatcher before calling a check's run_check_* function so
# finding() below knows which check to attribute its call to.
_ESCAL8_CURRENT_CHECK=""
declare -A ESCAL8_CHECK_STATUS
declare -A ESCAL8_CHECK_TOTAL
declare -A ESCAL8_CHECK_NONSKIP

# command_exists NAME
# Portable replacement for `which`: uses the shell builtin `command -v`,
# which POSIX guarantees, instead of assuming `which` or `type -p` exist.
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# have_readable PATH
# Used throughout for benign "can we read this to enumerate it" purposes
# (reading a config file to show its contents, etc.) - NOT for classifying
# something as a security misconfiguration. See escal8_effective_access
# below for that distinction.
have_readable() {
    [ -r "$1" ] 2>/dev/null
}

# escal8_is_root
# True if running with effective UID 0. Cached after first call since the
# answer cannot change mid-run.
_ESCAL8_IS_ROOT=""
escal8_is_root() {
    if [ -z "$_ESCAL8_IS_ROOT" ]; then
        if [ "$(id -u 2>/dev/null)" = "0" ]; then
            _ESCAL8_IS_ROOT=1
        else
            _ESCAL8_IS_ROOT=0
        fi
    fi
    [ "$_ESCAL8_IS_ROOT" = "1" ]
}

# escal8_mode_digits PATH
# Prints the last 3 permission digits (owner/group/other, e.g. "640") for
# PATH using whichever of GNU or BSD `stat` is available. Prints nothing
# and returns non-zero if `stat` is unavailable or the path can't be
# stat'd, so callers can distinguish "no access" from "don't know."
#
# Always dereferences symlinks (`stat -L`). A symlink's own permission
# bits are meaningless on Linux - they're always shown as rwxrwxrwx (777)
# regardless of the target's real permissions, because the kernel never
# enforces access against the symlink itself. /bin and /sbin are commonly
# symlinks to /usr/bin and /usr/sbin; stat'ing them without -L would read
# that meaningless 777 and misreport a perfectly normal system as
# world-writable. -L gives the target's actual, enforced permissions,
# which is what access control decisions are actually based on.
escal8_mode_digits() {
    local p="$1" m
    command_exists stat || return 1
    m="$(stat -L -c '%a' "$p" 2>/dev/null)"
    [ -z "$m" ] && m="$(stat -L -f '%Lp' "$p" 2>/dev/null)"
    [ -z "$m" ] && return 1
    printf '%s' "${m: -3}"
}

# escal8_effective_access PATH KIND
# KIND is "r" or "w". Answers "would this actually be exploitable" rather
# than "does the access()-style -r/-w test pass", which matters because
# root's DAC bypass makes -r/-w trivially true for virtually every file on
# the system and would otherwise flag essentially everything as a
# misconfiguration when Escal8 is run as root (the common case for a full
# host audit).
#
#   - When NOT running as root: -r/-w already reflect this exact user's
#     real, DAC-governed access, which is precisely the thing worth
#     flagging. No change from the original behavior.
#   - When running as root: -r/-w tell us nothing (always true), so instead
#     this checks the file's own "other" permission bit - i.e. "would a
#     generic non-owning, non-group user be able to do this" - which is
#     what actually distinguishes a real misconfiguration from root's
#     inherent, expected access to its own files.
#
# Returns: 0 = accessible/exploitable (report it), 1 = not accessible (no
# finding), 2 = unknown (couldn't determine - caller should SKIP, not guess
# in either direction).
escal8_effective_access() {
    local path="$1" kind="$2"

    if ! escal8_is_root; then
        if [ "$kind" = "w" ]; then
            [ -w "$path" ]
        else
            [ -r "$path" ]
        fi
        return $?
    fi

    local digits other_digit bitmask
    digits="$(escal8_mode_digits "$path")" || return 2
    other_digit="${digits:2:1}"
    case "$other_digit" in
        [0-7]) : ;;
        *) return 2 ;;
    esac
    if [ "$kind" = "w" ]; then bitmask=2; else bitmask=4; fi
    if (( (other_digit & bitmask) != 0 )); then
        return 0
    fi
    return 1
}

# _escal8_verify_secure_dir DIR
# Defense-in-depth check applied to any directory we're about to trust as
# our private workspace, whether it came from `mktemp` or our own manual
# fallback: it must genuinely exist, must NOT be a symlink (a symlink here
# would mean something other than our own mkdir call produced this path),
# must be a real directory, and must be owned by the user we're running as.
# This matters most when Escal8 runs as root: without these checks, an
# unprivileged local attacker could pre-plant a directory (or a symlink to
# one) at a predictable path and have root's enumeration run silently reuse
# and write into attacker-controlled storage.
_escal8_verify_secure_dir() {
    local d="$1"
    [ -n "$d" ] || return 1
    [ -L "$d" ] && return 1
    [ -e "$d" ] || return 1
    [ -d "$d" ] || return 1

    # `[ -O FILE ]` is a bash ownership test (true if FILE exists and its
    # owner is the effective user id of this process) - portable across
    # every environment that can run this script at all, since Escal8
    # already requires bash. This is the primary ownership control.
    [ -O "$d" ] || return 1

    # If `stat` happens to be available, cross-check numeric UID too, and
    # reject anything group- or world-accessible (we always chmod 700
    # ourselves, but a hostile or unusual filesystem/umask could still
    # surprise us, so verify rather than assume).
    if command_exists stat; then
        local owner mode
        owner="$(stat -c '%u' "$d" 2>/dev/null)"
        [ -z "$owner" ] && owner="$(stat -f '%u' "$d" 2>/dev/null)"
        if [ -n "$owner" ] && [ "$owner" != "$(id -u 2>/dev/null)" ]; then
            return 1
        fi
        mode="$(stat -c '%a' "$d" 2>/dev/null)"
        [ -z "$mode" ] && mode="$(stat -f '%Lp' "$d" 2>/dev/null)"
        if [ -n "$mode" ]; then
            case "$mode" in
                700|0700) : ;;
                *) return 1 ;;
            esac
        fi
    fi

    return 0
}

# _escal8_mkdir_secure DIR
# Attempts to create exactly one private directory at DIR. Relies on the
# POSIX guarantee that mkdir() fails with EEXIST if *anything* - a regular
# file, a directory, or a symlink (dangling or not) - already occupies that
# path; a trailing symlink is never followed for the final path component.
# That makes a bare `mkdir` (never `mkdir -p`, which happily reuses
# whatever is already there) the actual symlink/pre-creation defense. The
# umask is the primary control over the resulting mode (it applies however
# minimal the target's toolset is, since it's a shell builtin, not an
# external command); `chmod` afterward is belt-and-suspenders hardening,
# used only if present - its absence doesn't block Escal8 from running at
# all, since _escal8_verify_secure_dir still checks the resulting mode
# (via `stat`, when available) before anything is trusted.
#
# `mkdir` itself is the one genuinely new hard baseline this fix adds
# (previously it was used silently in an insecure fallback path; now it's
# required for Escal8 to run at all, same tier as bash itself - see
# docs/LIMITATIONS.md). Virtually every Unix-like target, including
# minimal BusyBox builds, ships it.
_escal8_mkdir_secure() {
    local d="$1"
    ( umask 077 && mkdir "$d" ) 2>/dev/null || return 1
    command_exists chmod && chmod 700 "$d" 2>/dev/null
    return 0
}

# escal8_secure_tmpdir
# Manual fallback for creating a private temp directory when `mktemp` is
# unavailable. Tries a handful of randomized, hard-to-predict candidate
# paths (never a predictable `/tmp/.escal8_$$`-style name) under TMPDIR (or
# /tmp), and verifies each one before trusting it. Prints the resulting
# path on success; produces no output and returns non-zero on failure, so
# callers can fail closed instead of silently continuing without a safe
# workspace.
escal8_secure_tmpdir() {
    local base="${TMPDIR:-/tmp}"
    [ -d "$base" ] || return 1
    [ -w "$base" ] || return 1

    local attempt candidate rand
    for attempt in 1 2 3 4 5 6 7 8 9 10; do
        rand="${RANDOM}${RANDOM}${RANDOM}_$$_${attempt}"
        candidate="$base/.escal8.$rand"
        if _escal8_mkdir_secure "$candidate"; then
            if _escal8_verify_secure_dir "$candidate"; then
                printf '%s' "$candidate"
                return 0
            fi
            # Created but failed verification: should not happen under
            # normal POSIX semantics, but don't trust it - clean up and
            # give up rather than silently fall back to something unsafe.
            rmdir "$candidate" 2>/dev/null
            return 1
        fi
    done
    return 1
}

# escal8_init_runtime
# Creates the private temp workspace used to buffer findings for reporting.
# Prefers `mktemp -d`, which already creates its directory atomically with
# 0700 permissions; falls back to escal8_secure_tmpdir() when `mktemp` is
# unavailable. Every candidate directory is verified with
# _escal8_verify_secure_dir before use. If no secure directory can be
# created and verified, Escal8 fails closed: it prints a clear error and
# exits rather than continuing without a trustworthy workspace - this is a
# deliberate change from silently degrading, since writing findings through
# an attacker-controlled path is unsafe, especially when running as root.
escal8_init_runtime() {
    if command_exists mktemp; then
        ESCAL8_TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/escal8.XXXXXXXXXX" 2>/dev/null)"
        if [ -n "$ESCAL8_TMPDIR" ]; then
            command_exists chmod && chmod 700 "$ESCAL8_TMPDIR" 2>/dev/null
            if ! _escal8_verify_secure_dir "$ESCAL8_TMPDIR"; then
                rm -rf -- "$ESCAL8_TMPDIR" 2>/dev/null
                ESCAL8_TMPDIR=""
            fi
        fi
    fi

    if [ -z "$ESCAL8_TMPDIR" ]; then
        ESCAL8_TMPDIR="$(escal8_secure_tmpdir)"
    fi

    if [ -z "$ESCAL8_TMPDIR" ] || ! _escal8_verify_secure_dir "$ESCAL8_TMPDIR"; then
        echo "Escal8: could not create and verify a secure private temp directory under \"${TMPDIR:-/tmp}\"." >&2
        echo "Escal8: refusing to continue (fail closed) - check that the directory exists, is writable, and is not pre-occupied by another user's files or a symlink." >&2
        exit 3
    fi

    ESCAL8_FINDINGS_FILE="$ESCAL8_TMPDIR/findings.tsv"
    : > "$ESCAL8_FINDINGS_FILE" 2>/dev/null
    if [ ! -f "$ESCAL8_FINDINGS_FILE" ]; then
        echo "Escal8: could not create the findings buffer file inside the secure temp directory - refusing to continue." >&2
        exit 3
    fi
}

escal8_cleanup_runtime() {
    if [ -n "$ESCAL8_TMPDIR" ] && [ -d "$ESCAL8_TMPDIR" ] && [ ! -L "$ESCAL8_TMPDIR" ]; then
        rm -rf -- "$ESCAL8_TMPDIR" 2>/dev/null
    fi
}

# _escal8_encode / _escal8_decode: collapse newlines/pipes so a multi-line
# detail string can round-trip through a single TSV line safely.
_escal8_encode() {
    printf '%s' "$1" | awk '{ if (NR>1) printf "\\n"; printf "%s", $0 }' | sed 's/|/\\x7c/g'
}
_escal8_decode() {
    printf '%s' "$1" | sed 's/\\x7c/|/g; s/\\n/\n/g'
}

# section HEADING
# Prints a progressive section banner (skipped entirely in --quiet mode,
# where only the final summary + any CRITICAL/HIGH findings are shown).
section() {
    [ "$ESCAL8_QUIET" -eq 1 ] && return 0
    printf '\n%s[+] %s%s\n' "${C_BOLD}${C_MAGENTA}" "$1" "$C_RESET"
}

subsection() {
    [ "$ESCAL8_QUIET" -eq 1 ] && return 0
    printf '%s  -> %s%s\n' "${C_CYAN}" "$1" "$C_RESET"
}

# finding SEVERITY CHECK_ID TITLE [DETAIL]
# The single consistent interface every check module uses to report a result.
# Writes to the live terminal (unless quiet suppresses low-severity noise)
# and always appends a record to the findings file for the summary/report.
finding() {
    local sev="$1" id="$2" title="$3" detail="${4:-}"
    ESCAL8_COUNTS[$sev]=$(( ${ESCAL8_COUNTS[$sev]:-0} + 1 ))

    if [ -n "$_ESCAL8_CURRENT_CHECK" ]; then
        ESCAL8_CHECK_TOTAL[$_ESCAL8_CURRENT_CHECK]=$(( ${ESCAL8_CHECK_TOTAL[$_ESCAL8_CURRENT_CHECK]:-0} + 1 ))
        if [ "$sev" != "SKIP" ]; then
            ESCAL8_CHECK_NONSKIP[$_ESCAL8_CURRENT_CHECK]=$(( ${ESCAL8_CHECK_NONSKIP[$_ESCAL8_CURRENT_CHECK]:-0} + 1 ))
        fi
    fi

    local encoded
    encoded="$(_escal8_encode "$detail")"
    printf '%s|%s|%s|%s\n' "$sev" "$id" "$title" "$encoded" >> "$ESCAL8_FINDINGS_FILE"

    if [ "$ESCAL8_QUIET" -eq 1 ]; then
        case "$sev" in CRITICAL|HIGH|FAILED) : ;; *) return 0 ;; esac
    fi

    local color; color="$(_escal8_sev_color "$sev")"
    printf '    [%s%-8s%s] %s\n' "$color" "$sev" "$C_RESET" "$title"
    if [ -n "$detail" ] && [ "$sev" != "OK" ] && [ "$sev" != "SKIP" ]; then
        printf '%s\n' "$detail" | while IFS= read -r line; do
            [ -n "$line" ] && printf '        %s%s%s\n' "$C_DIM" "$line" "$C_RESET"
        done
    fi
}

# skip_check CHECK_ID TITLE REASON
# Explicitly distinguishes "we did not look" from "we looked and it's clean".
# This matters for report accuracy per the project's documentation policy.
skip_check() {
    finding "SKIP" "$1" "$2 (skipped: $3)" ""
}

# run_safe CMD...
# Executes a command defensively: redirects stderr, never aborts the script,
# and returns empty output (rather than erroring) if the tool is missing.
run_safe() {
    local cmd="$1"; shift
    if ! command_exists "$cmd"; then
        return 127
    fi
    "$cmd" "$@" 2>/dev/null
    return $?
}

human_time() {
    date '+%Y-%m-%d %H:%M:%S %Z' 2>/dev/null || date 2>/dev/null || echo "unknown"
}

# ============================== 03_args.sh ==============================
# ------------------------------------------------------------------------------
# CLI argument parsing
# ------------------------------------------------------------------------------

# All checks the tool knows about, in execution order. Keep this list and the
# corresponding `run_<name>` function names (see 99_main.sh) in sync.
ESCAL8_ALL_CHECKS="system users sudo suid capabilities cron writable path network services processes containers nfs ssh historyenv credentials acl sudotokens mounts software kernel systemd_timers polkit kernel_hardening deleted_files cloud devops system_surfaces"

# Profiles are named subsets of ESCAL8_ALL_CHECKS.
#   quick :  fast, high-signal checks only (good for noisy/monitored targets)
#   full  :  every check (default)
#   stealth: minimal filesystem traversal / fewer processes spawned
ESCAL8_PROFILE="full"
ESCAL8_CHECKS_OVERRIDE=""   # set via --checks, comma separated, overrides profile

escal8_usage() {
    cat <<EOF
${ESCAL8_NAME} v${ESCAL8_VERSION} - Linux privilege escalation enumeration

USAGE:
    bash escal8.sh [OPTIONS]

OPTIONS:
    -h, --help                Show this help message and exit
    -v, --version             Show version information and exit
    -p, --profile NAME        Check profile: quick | full | stealth (default: full)
    -c, --checks LIST         Comma-separated list of checks to run, overrides --profile
                               Available: ${ESCAL8_ALL_CHECKS// /, }
        --no-color             Disable ANSI colors in terminal output
    -q, --quiet                Only print CRITICAL/HIGH findings and the final summary
    -o, --output FILE          Write a report to FILE (format from --format, default text)
    -f, --format FORMAT        Report format: text | json | html (default: text)
        --list-checks          List available checks and exit

EXAMPLES:
    bash escal8.sh
    bash escal8.sh --profile quick --no-color
    bash escal8.sh --checks suid,sudo,cron -o report.txt
    bash escal8.sh --format json --output findings.json

EXIT CODES:
    0    No CRITICAL or HIGH findings
    1    At least one HIGH finding, no CRITICAL
    2    At least one CRITICAL finding, OR invalid command-line usage
    3    Could not create a secure private workspace - refused to run

NOTES:
    - This tool is strictly read-only enumeration. It never modifies system
      state and never attempts to actually escalate privileges.
    - Intended for use in environments you are authorized to test: CTF
      ranges, HTB/THM boxes, and scoped penetration-testing engagements.
    - Checks that require a missing utility are explicitly reported as
      SKIPPED, never silently omitted, so gaps in coverage are visible.
    - An unknown name in --checks or an unknown --profile is a hard error
      (exit code 2), not a silently-ignored no-op.
    - Every run ends with a "Check Coverage" section distinguishing checks
      that completed, were skipped (ran, but could assess nothing at all),
      failed (an internal Escal8 error, not a target finding), or simply
      weren't requested this run.
EOF
}

escal8_version() {
    printf '%s v%s\n' "$ESCAL8_NAME" "$ESCAL8_VERSION"
}

escal8_list_checks() {
    echo "Available checks:"
    for c in $ESCAL8_ALL_CHECKS; do
        printf '  - %s\n' "$c"
    done
}

# escal8_is_known_check NAME
# True if NAME is one of the checks Escal8 actually implements (i.e.
# appears in ESCAL8_ALL_CHECKS).
escal8_is_known_check() {
    local name="$1" c
    for c in $ESCAL8_ALL_CHECKS; do
        [ "$c" = "$name" ] && return 0
    done
    return 1
}

# profile_to_checks NAME -> prints space separated check list
profile_to_checks() {
    case "$1" in
        full)
            printf '%s' "$ESCAL8_ALL_CHECKS"
            ;;
        quick)
            printf '%s' "system sudo suid capabilities cron path processes kernel cloud devops"
            ;;
        stealth)
            # Avoids broad filesystem traversal (writable/suid full scans) and
            # avoids spawning extra network/process enumeration subprocesses.
            printf '%s' "system sudo capabilities cron historyenv"
            ;;
        *)
            printf ''
            ;;
    esac
}

escal8_parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -h|--help)
                escal8_usage
                exit 0
                ;;
            -v|--version)
                escal8_version
                exit 0
                ;;
            -p|--profile)
                [ $# -ge 2 ] || { echo "Error: --profile requires an argument" >&2; exit 2; }
                ESCAL8_PROFILE="$2"
                shift 2
                ;;
            --profile=*)
                ESCAL8_PROFILE="${1#*=}"
                shift
                ;;
            -c|--checks)
                [ $# -ge 2 ] || { echo "Error: --checks requires an argument" >&2; exit 2; }
                ESCAL8_CHECKS_OVERRIDE="$2"
                shift 2
                ;;
            --checks=*)
                ESCAL8_CHECKS_OVERRIDE="${1#*=}"
                shift
                ;;
            --no-color)
                ESCAL8_NO_COLOR=1
                shift
                ;;
            -q|--quiet)
                ESCAL8_QUIET=1
                shift
                ;;
            -o|--output)
                [ $# -ge 2 ] || { echo "Error: --output requires an argument" >&2; exit 2; }
                ESCAL8_OUTFILE="$2"
                shift 2
                ;;
            --output=*)
                ESCAL8_OUTFILE="${1#*=}"
                shift
                ;;
            -f|--format)
                [ $# -ge 2 ] || { echo "Error: --format requires an argument" >&2; exit 2; }
                ESCAL8_FORMAT="$2"
                shift 2
                ;;
            --format=*)
                ESCAL8_FORMAT="${1#*=}"
                shift
                ;;
            --list-checks)
                escal8_list_checks
                exit 0
                ;;
            *)
                echo "Unknown option: $1" >&2
                echo "Run 'bash escal8.sh --help' for usage." >&2
                exit 2
                ;;
        esac
    done

    case "$ESCAL8_FORMAT" in
        text|json|html) : ;;
        *)
            echo "Error: unsupported --format '$ESCAL8_FORMAT' (use text, json, or html)" >&2
            exit 2
            ;;
    esac

    if [ -n "$ESCAL8_CHECKS_OVERRIDE" ]; then
        ESCAL8_SELECTED_CHECKS="$(printf '%s' "$ESCAL8_CHECKS_OVERRIDE" | tr ',' ' ')"

        # Reject unknown check names outright rather than silently dropping
        # them: a typo in --checks should never result in Escal8 quietly
        # running fewer checks than the person asked for and reporting
        # success regardless.
        local unknown="" c
        for c in $ESCAL8_SELECTED_CHECKS; do
            if ! escal8_is_known_check "$c"; then
                unknown="$unknown $c"
            fi
        done
        if [ -n "$unknown" ]; then
            echo "Error: unknown check(s) in --checks:$unknown" >&2
            echo "Available checks: ${ESCAL8_ALL_CHECKS// /, }" >&2
            exit 2
        fi
    else
        ESCAL8_SELECTED_CHECKS="$(profile_to_checks "$ESCAL8_PROFILE")"
        if [ -z "$ESCAL8_SELECTED_CHECKS" ]; then
            echo "Error: unknown profile '$ESCAL8_PROFILE' (use quick, full, or stealth)" >&2
            exit 2
        fi
    fi
}

# ============================== 10_check_system.sh ==============================
# ------------------------------------------------------------------------------
# Check: system / OS fingerprinting
# ------------------------------------------------------------------------------

run_check_system() {
    section "System Information"

    local kernel arch hostname
    kernel="$(run_safe uname -a)"
    arch="$(run_safe uname -m)"
    hostname="$(run_safe hostname)"

    if [ -n "$kernel" ]; then
        finding "INFO" "system.kernel" "Kernel: $kernel" ""
    else
        skip_check "system.kernel" "Kernel version" "uname not available"
    fi

    [ -n "$hostname" ] && finding "INFO" "system.hostname" "Hostname: $hostname" ""

    if have_readable /etc/os-release; then
        local pretty
        pretty="$(grep -m1 '^PRETTY_NAME=' /etc/os-release 2>/dev/null | sed 's/^PRETTY_NAME=//' | tr -d '"')"
        [ -n "$pretty" ] && finding "INFO" "system.distro" "Distribution: $pretty" ""
    elif have_readable /etc/issue; then
        finding "INFO" "system.distro" "Distribution (from /etc/issue): $(head -n1 /etc/issue 2>/dev/null)" ""
    else
        skip_check "system.distro" "Distribution identification" "no /etc/os-release or /etc/issue"
    fi

    # CPU/arch context matters for exploit applicability (e.g. 32 vs 64-bit).
    [ -n "$arch" ] && finding "INFO" "system.arch" "Architecture: $arch" ""

    # Container / virtualization hints - affects which escalation paths apply.
    local container_hint=""
    if have_readable /.dockerenv; then
        container_hint="/.dockerenv present"
    elif have_readable /proc/1/cgroup && grep -qE 'docker|lxc|kubepods' /proc/1/cgroup 2>/dev/null; then
        container_hint="cgroup references docker/lxc/kubepods"
    fi
    if [ -n "$container_hint" ]; then
        finding "MEDIUM" "system.container" "Host appears to be a container" "$container_hint"
    else
        finding "OK" "system.container" "No obvious container indicators" ""
    fi

    # Uptime / boot time: an old uptime without reboot can indicate unpatched
    # kernel is still in use even after a vendor fix was installed.
    if command_exists uptime; then
        finding "INFO" "system.uptime" "Uptime: $(uptime 2>/dev/null)" ""
    else
        skip_check "system.uptime" "Uptime" "uptime not available"
    fi

    # Sudo/package manager hints about patch level, without assuming any
    # particular package manager exists.
    if command_exists dpkg; then
        finding "INFO" "system.pkgmgr" "Package manager: dpkg/apt detected" ""
    elif command_exists rpm; then
        finding "INFO" "system.pkgmgr" "Package manager: rpm detected" ""
    elif command_exists apk; then
        finding "INFO" "system.pkgmgr" "Package manager: apk (Alpine) detected" ""
    else
        skip_check "system.pkgmgr" "Package manager identification" "no known package manager found"
    fi
    return 0
}

# ============================== 11_check_users.sh ==============================
# ------------------------------------------------------------------------------
# Check: users and groups
# ------------------------------------------------------------------------------

run_check_users() {
    section "Users & Groups"

    local who; who="$(run_safe id)"
    [ -n "$who" ] && finding "INFO" "users.whoami" "Current identity: $who" ""

    # Interesting group membership that often grants indirect root paths.
    local groups_str; groups_str="$(run_safe id -nG)"
    if [ -n "$groups_str" ]; then
        for g in docker lxd adm disk video root wheel shadow; do
            case " $groups_str " in
                *" $g "*)
                    case "$g" in
                        docker|lxd|disk|shadow)
                            finding "HIGH" "users.group.$g" "User is a member of the '$g' group" \
                                "Membership in '$g' commonly allows privilege escalation to root."
                            ;;
                        adm|video)
                            finding "MEDIUM" "users.group.$g" "User is a member of the '$g' group" \
                                "May grant access to logs or device files useful for further enumeration."
                            ;;
                        *)
                            finding "INFO" "users.group.$g" "User is a member of the '$g' group" ""
                            ;;
                    esac
                    ;;
            esac
        done
    else
        skip_check "users.groups" "Group membership" "id -nG unavailable"
    fi

    # Accounts with UID 0 other than root are an instant red flag.
    if have_readable /etc/passwd; then
        local uid0
        uid0="$(awk -F: '$3 == 0 { print $1 }' /etc/passwd 2>/dev/null | grep -v '^root$')"
        if [ -n "$uid0" ]; then
            finding "CRITICAL" "users.uid0" "Non-root account(s) with UID 0" "$uid0"
        else
            finding "OK" "users.uid0" "Only 'root' has UID 0" ""
        fi

        # Accounts with a login shell that might be usable interactively.
        local shells
        shells="$(awk -F: '$7 !~ /(nologin|false)$/ { print $1 ":" $7 }' /etc/passwd 2>/dev/null)"
        [ -n "$shells" ] && finding "INFO" "users.shells" "Accounts with an interactive shell" "$shells"
    else
        skip_check "users.passwd" "/etc/passwd analysis" "file not readable"
    fi

    # World-readable/writable shadow file would be catastrophic. Running as
    # root always passes a plain -r/-w test (root bypasses DAC), so that is
    # not itself a misconfiguration - escal8_effective_access instead
    # checks whether a non-root, non-group user could read/write it when
    # we're root, and falls back to the original direct test otherwise.
    if [ -e /etc/shadow ]; then
        escal8_effective_access /etc/shadow r
        case $? in
            0)
                finding "CRITICAL" "users.shadow_readable" "/etc/shadow is readable by unprivileged users" \
                    "Password hashes may be extractable for offline cracking."
                ;;
            2)
                skip_check "users.shadow_readable" "/etc/shadow readability" \
                    "running as root and 'stat' is unavailable, so the actual permission bits could not be inspected"
                ;;
        esac

        escal8_effective_access /etc/shadow w
        case $? in
            0)
                finding "CRITICAL" "users.shadow_writable" "/etc/shadow is writable by unprivileged users" \
                    "Password hashes could be overwritten to take over any account, including root."
                ;;
            2)
                skip_check "users.shadow_writable" "/etc/shadow writability" \
                    "running as root and 'stat' is unavailable, so the actual permission bits could not be inspected"
                ;;
        esac
    fi
    return 0
}

# ============================== 12_check_sudo.sh ==============================
# ------------------------------------------------------------------------------
# Check: sudo configuration
# ------------------------------------------------------------------------------

# A short, well-known list of GTFOBins-style sudo-exploitable binaries.
# Kept intentionally small/representative - this is a heuristic hint, not an
# exhaustive exploit database, and Escal8 never tries to use these itself.
_ESCAL8_SUDO_RISKY_BINS="vim vi view nano pico emacs less more pager find xargs awk gawk mawk sed perl perl5 python python2 python3 python3.8 python3.9 python3.10 python3.11 python3.12 pypy ruby irb php node nodejs lua luajit tclsh wish gdb strace ltrace env tee cp mv install chmod chown chgrp rsync tar zip unzip 7z busybox bash sh dash zsh ksh fish ash expect socat nc ncat netcat nmap tcpdump mysql psql sqlite3 ftp sftp ssh scp git docker podman kubectl runc systemctl journalctl mount umount dd cpio rpm dpkg apt apt-get yum dnf apk snap screen tmux script chroot unshare nsenter setcap setfacl passwd usermod groupmod useradd groupadd aria2c curl wget openssl gnuplot hping3 ionice ip jq ldapsearch logsave mail nice nohup pip pip3 pkexec start-stop-daemon telnet time watch xdg-user-dir xdotool zipinfo taskset ed ex gtester run-parts flock fuser lsof man-db socat ncat nc.traditional"

run_check_sudo() {
    section "Sudo Configuration"

    if ! command_exists sudo; then
        skip_check "sudo.list" "sudo privileges" "sudo not installed"
        return 0
    fi

    # -n (non-interactive) ensures we never hang or prompt for a password;
    # if it fails we just report that we couldn't check non-interactively.
    local out rc
    out="$(sudo -n -l 2>&1)"
    rc=$?

    if [ $rc -ne 0 ]; then
        finding "INFO" "sudo.list" "Could not list sudo privileges non-interactively" \
            "Either a password is required or the user has no sudo access."
        return 0
    fi

    finding "INFO" "sudo.list" "sudo -l output" "$out"

    if printf '%s' "$out" | grep -q 'NOPASSWD'; then
        finding "INFO" "sudo.nopasswd" "User has one or more NOPASSWD sudo entries" \
            "Passwordless sudo is not automatically privilege escalation; review each permitted command, arguments, run-as identity, and environment restrictions."
    fi

    if printf '%s' "$out" | grep -qE '\(ALL([[:space:]]*:[[:space:]]*ALL)?\)[[:space:]]*ALL'; then
        finding "CRITICAL" "sudo.all" "User can sudo as ALL users running ALL commands" \
            "Effectively equivalent to a direct root shell via 'sudo su' or similar."
    fi

    # Parse actual command entries and only assign HIGH to entries that can
    # run as root or ALL. A rule such as (daemon) /usr/bin/vim may be unusual,
    # but is not by itself a root-privilege escalation path. Do not treat a
    # binary name in a comment/header as an allowed command. Sudoers aliases,
    # command arguments, tags, plugins, and Defaults can still affect meaning;
    # this remains a review heuristic, not an exploitability proof.
    local sudo_line runas_spec command_spec command_name bin runas_root
    local sudo_entry_re='^[[:space:]]*\(([^)]*)\)[[:space:]]*(.*)$'
    local root_runas_re='(^|,)[[:space:]]*(root|ALL)[[:space:]]*(,|:|$)'
    while IFS= read -r sudo_line; do
        [[ "$sudo_line" =~ $sudo_entry_re ]] || continue
        runas_spec="${BASH_REMATCH[1]}"
        command_spec="${BASH_REMATCH[2]}"
        # Remove common sudo tags only at the beginning of the command list.
        while [[ "$command_spec" =~ ^(NOPASSWD|PASSWD|SETENV|NOSETENV|LOG_INPUT|NOLOG_INPUT|LOG_OUTPUT|NOLOG_OUTPUT):[[:space:]]*(.*)$ ]]; do
            command_spec="${BASH_REMATCH[2]}"
        done
        command_spec="${command_spec%%,*}"
        command_spec="${command_spec# }"
        command_spec="${command_spec%%[[:space:]]*}"
        [ -n "$command_spec" ] || continue
        runas_root=0
        # sudoers permits comma-separated run-as user lists. ALL may include
        # root; a named non-root identity must not be treated as root access.
        if [[ ",$runas_spec," =~ $root_runas_re ]]; then
            runas_root=1
        fi
        [ "$runas_root" -eq 1 ] || continue
        command_name="${command_spec##*/}"
        for bin in $_ESCAL8_SUDO_RISKY_BINS; do
            if [ "$command_name" = "$bin" ]; then
                finding "HIGH" "sudo.gtfobin.$bin" "Root/ALL sudo command entry matches commonly abusable program '$bin'" \
                    "Heuristic only. Verify the exact allowed arguments, run-as identity, environment restrictions, aliases, and binary behavior before concluding privilege escalation is possible."
                break
            fi
        done
    done <<EOF_SUDO_RISKY_LINES
$out
EOF_SUDO_RISKY_LINES

    # A command explicitly allowed as root/ALL and writable by this user is a
    # much stronger signal than NOPASSWD alone. Inspect only literal absolute
    # executable paths from sudo -l output; do not execute any listed command.
    if ! escal8_is_root; then
        local sudo_line sudo_cmd
        while IFS= read -r sudo_line; do
            printf '%s\n' "$sudo_line" | grep -Eq '^[[:space:]]*\((root|ALL)([[:space:]:)]|$)' || continue
            sudo_cmd="$(printf '%s\n' "$sudo_line" | sed -nE 's/^[[:space:]]*\([^)]*\)[[:space:]]*(NOPASSWD:[[:space:]]*)?(PASSWD:[[:space:]]*)?(SETENV:[[:space:]]*)?(NOSETENV:[[:space:]]*)?([^[:space:]]+).*/\5/p')"
            case "$sudo_cmd" in
                /*)
                    if [ -f "$sudo_cmd" ] && [ -w "$sudo_cmd" ]; then
                        finding "HIGH" "sudo.writable_command" "Sudo-allowed command is writable by the current user: $sudo_cmd" \
                            "A root-authorized command path writable by this user can permit code modification. Verify sudoers arguments and the exact file before concluding exploitability."
                    fi
                    ;;
            esac
        done <<EOF_SUDO_LINES
$out
EOF_SUDO_LINES
    fi

    # sudo version can itself be vulnerable (e.g. CVE-2021-3156 'Baron Samedit').
    local sver; sver="$(run_safe sudo -V | head -n1)"
    [ -n "$sver" ] && finding "INFO" "sudo.version" "sudo version: $sver" \
        "Cross-reference this version against known sudo CVEs."
    return 0
}

# ============================== 13_check_suid.sh ==============================
# ------------------------------------------------------------------------------
# Check: SUID / SGID binaries
# ------------------------------------------------------------------------------

# Candidate list is deliberately a heuristic subset of GTFOBins, not a complete
# replacement for LinPEAS's generated GTFOBins-derived matching database.
_ESCAL8_SUID_KNOWN_RISKY="nmap vim vi view nano pico emacs find xargs awk gawk sed perl perl5 python python2 python3 python3.8 python3.9 python3.10 python3.11 python3.12 pypy ruby irb php node nodejs lua luajit gcc cc clang gdb strace ltrace env tee cp mv install chmod chown chgrp rsync tar zip unzip 7z busybox bash sh dash zsh ksh fish ash expect socat nc ncat netcat nmap tcpdump mysql psql sqlite3 ftp git docker podman kubectl runc systemctl journalctl mount umount dd cpio rpm dpkg apt apt-get yum dnf apk snap screen tmux script chroot unshare nsenter setcap setfacl passwd usermod groupmod useradd groupadd"

run_check_suid() {
    section "SUID / SGID Binaries"

    if ! command_exists find; then
        skip_check "suid.scan" "SUID/SGID filesystem scan" "find not available"
        return 0
    fi

    # Scan the root filesystem once and bound traversal time. Large /opt or
    # language-package trees can otherwise stall enumeration for minutes. A
    # timeout is reported as partial coverage, never as a clean result.
    # Additional persistent mounts are scanned only after the root scan
    # completes, and each distinct device is visited at most once.
    local suid_file="$ESCAL8_TMPDIR/suid_list.txt"
    local sgid_file="$ESCAL8_TMPDIR/sgid_list.txt"
    local all_file="$ESCAL8_TMPDIR/suid_sgid_all.txt"
    local raw_file="$ESCAL8_TMPDIR/suid_sgid_raw.txt"
    local scan_timeout="${ESCAL8_FIND_TIMEOUT:-20}"
    case "$scan_timeout" in ''|*[!0-9]*) scan_timeout=20 ;; esac
    [ "$scan_timeout" -gt 0 ] || scan_timeout=20
    : > "$suid_file"; : > "$sgid_file"; : > "$raw_file"
    local scan_rc=0
    if command_exists timeout; then
        timeout "${scan_timeout}s" find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune -o -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null > "$raw_file"
        scan_rc=$?
    else
        find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune -o -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null > "$raw_file"
        scan_rc=$?
    fi
    local bin
    while IFS= read -r bin; do
        [ -n "$bin" ] || continue
        [[ -u "$bin" ]] && printf '%s\n' "$bin" >> "$suid_file"
        [[ -g "$bin" ]] && printf '%s\n' "$bin" >> "$sgid_file"
    done < "$raw_file"
    if [ "$scan_rc" -eq 0 ] && command_exists findmnt && command_exists stat; then
        local root_dev mountpoint mount_dev
        root_dev="$(stat -Lc '%d' / 2>/dev/null)"
        declare -A _escal8_seen_mount_devices=()
        [ -n "$root_dev" ] && _escal8_seen_mount_devices["$root_dev"]=1
        while IFS= read -r mountpoint; do
            case "$mountpoint" in /|/proc|/proc/*|/sys|/sys/*|/dev|/dev/*|/run|/run/*) continue ;; esac
            [ -d "$mountpoint" ] || continue
            mount_dev="$(stat -Lc '%d' "$mountpoint" 2>/dev/null)"
            [ -n "$mount_dev" ] || continue
            [ -z "${_escal8_seen_mount_devices[$mount_dev]:-}" ] || continue
            _escal8_seen_mount_devices["$mount_dev"]=1
            if command_exists timeout; then
                timeout "${scan_timeout}s" find "$mountpoint" -xdev -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null > "$ESCAL8_TMPDIR/mount_suid_sgid.txt"
                local mount_rc=$?
                if [ "$mount_rc" -ne 0 ]; then
                    finding INFO "suid.mount_scan_partial" "SUID/SGID scan of mount was incomplete: $mountpoint" "A per-filesystem scan exceeded its time limit or failed; findings from this mount may be incomplete."
                    continue
                fi
            else
                find "$mountpoint" -xdev -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null > "$ESCAL8_TMPDIR/mount_suid_sgid.txt"
            fi
            while IFS= read -r bin; do
                [ -n "$bin" ] || continue
                [[ -u "$bin" ]] && printf '%s\n' "$bin" >> "$suid_file"
                [[ -g "$bin" ]] && printf '%s\n' "$bin" >> "$sgid_file"
            done < "$ESCAL8_TMPDIR/mount_suid_sgid.txt"
        done < <(findmnt -rn -t ext2,ext3,ext4,xfs,btrfs,zfs,nfs,nfs4,cifs,fuseblk,vfat,exfat,ntfs -o TARGET 2>/dev/null)
    fi
    sort -u "$suid_file" -o "$suid_file" 2>/dev/null
    sort -u "$sgid_file" -o "$sgid_file" 2>/dev/null
    cat "$suid_file" "$sgid_file" | sort -u > "$all_file"
    if [ "$scan_rc" -eq 124 ] || [ "$scan_rc" -eq 137 ]; then
        finding INFO "suid.scan_timeout" "SUID/SGID scan reached its ${scan_timeout}s time limit; results are partial" "Increase ESCAL8_FIND_TIMEOUT to allow a longer scan. Partial results must not be interpreted as a complete inventory."
    fi

    local suid_count sgid_count total_count
    suid_count="$(wc -l < "$suid_file" 2>/dev/null | tr -d ' ')"
    sgid_count="$(wc -l < "$sgid_file" 2>/dev/null | tr -d ' ')"
    total_count="$(wc -l < "$all_file" 2>/dev/null | tr -d ' ')"
    suid_count="${suid_count:-0}"; sgid_count="${sgid_count:-0}"; total_count="${total_count:-0}"

    # Non-zero find status may still yield usable paths if traversal hits
    # restricted directories. Preserve those results and disclose partial coverage.
    if [ "$scan_rc" -ne 0 ] && [ "$scan_rc" -ne 124 ] && [ "$scan_rc" -ne 137 ]; then
        if [ "$total_count" -gt 0 ]; then
            finding INFO "suid.scan_partial" "SUID/SGID scan was partial; results were collected" "find exit status: $scan_rc; found $suid_count SUID and $sgid_count SGID files. Access restrictions may hide additional files."
        else
            finding SKIP "suid.scan_error" "SUID/SGID scan returned an error and no results" "find exit status: $scan_rc; no usable inventory was collected."
        fi
    fi

    if [ "$total_count" -eq 0 ]; then
        finding "INFO" "suid.scan_empty" "No SUID/SGID results were returned" "This may mean no matching files were found or filesystem traversal was restricted; check scan permissions and mounted filesystems."
        return 0
    fi

    # Never dump an unbounded filesystem inventory into terminal or JSON/HTML
    # reports. Shared build/container environments can legitimately have huge
    # SGID trees; report totals plus a bounded sample and an explicit truncation
    # notice so output size remains predictable.
    local inventory_limit=100 suid_sample sgid_sample
    suid_sample="$(head -n "$inventory_limit" "$suid_file" 2>/dev/null)"
    sgid_sample="$(head -n "$inventory_limit" "$sgid_file" 2>/dev/null)"
    finding "INFO" "suid.count" "Found $suid_count SUID and $sgid_count SGID files" "SUID sample (up to $inventory_limit):
${suid_sample:-<none>}
SGID sample (up to $inventory_limit):
${sgid_sample:-<none>}"
    if [ "$suid_count" -gt "$inventory_limit" ] || [ "$sgid_count" -gt "$inventory_limit" ]; then
        finding "INFO" "suid.inventory_truncated" "SUID/SGID inventory sample truncated" \
            "The full inventory is intentionally not embedded in reports. Counts are complete only if the filesystem scan completed; the displayed path samples are limited to $inventory_limit entries per class."
    fi

    while IFS= read -r bin; do
        [ -n "$bin" ] || continue
        local base
        base="$(basename "$bin" 2>/dev/null)"
        for risky in $_ESCAL8_SUID_KNOWN_RISKY; do
            if [ "$base" = "$risky" ]; then
                finding "MEDIUM" "suid.risky.$base" "SUID binary matches a commonly abusable program: $bin" \
                    "Name-based matching alone does not establish an exploitable privilege-escalation path. Verify file ownership, version, effective SUID behavior, and the exact GTFOBins technique before assigning higher severity."
                break
            fi
        done
    done < "$suid_file"

    local unusual
    local unusual_count
    unusual_count="$(grep -vcE '^/(usr/bin|usr/sbin|bin|sbin|usr/lib|usr/libexec)/' "$all_file" 2>/dev/null)"
    unusual_count="${unusual_count:-0}"
    if [ "$unusual_count" -gt 0 ]; then
        unusual="$(grep -vE '^/(usr/bin|usr/sbin|bin|sbin|usr/lib|usr/libexec)/' "$all_file" 2>/dev/null | head -n 100)"
        finding "MEDIUM" "suid.unusual_location" "SUID/SGID files outside common system directories (review provenance; $unusual_count total)" "$unusual"
        if [ "$unusual_count" -gt 100 ]; then
            finding "INFO" "suid.unusual_location_truncated" "Unusual-location listing truncated" \
                "Showing the first 100 paths only. Review the complete inventory with a dedicated, controlled filesystem audit if required."
        fi
    fi
    return 0
}

# ============================== 14_check_capabilities.sh ==============================
# ------------------------------------------------------------------------------
# Check: Linux capabilities (cap_setuid, cap_dac_override, etc.)
# ------------------------------------------------------------------------------

_ESCAL8_RISKY_CAPS="cap_setuid cap_setgid cap_dac_override cap_dac_read_search cap_sys_admin cap_sys_ptrace cap_sys_module cap_sys_rawio"

run_check_capabilities() {
    section "File Capabilities"

    if command_exists getcap; then
        local out
        # Not every getcap supports -r (recursive); try it, fall back to a
        # manual find+getcap walk if it errors out.
        out="$(getcap -r / 2>/dev/null)"
        if [ -z "$out" ] && command_exists find; then
            out="$(find / -xdev -type f -exec getcap {} \; 2>/dev/null | grep -v '^$')"
        fi

        if [ -z "$out" ]; then
            finding "OK" "capabilities.none" "No file capabilities found" ""
            return 0
        fi

        finding "INFO" "capabilities.list" "Files with capabilities set" "$out"

        for cap in $_ESCAL8_RISKY_CAPS; do
            if printf '%s\n' "$out" | grep -Eq "(^|[[:space:],])${cap}([+ ,=]|$)"; then
                case "$cap" in
                    cap_setuid|cap_setgid|cap_dac_override|cap_dac_read_search|cap_sys_module)
                        finding "HIGH" "capabilities.risky.$cap" "A file holds the potentially high-impact capability '$cap'" \
                            "Capability presence is not proof of exploitable privilege escalation. Verify the exact file, effective/permitted flags, execution context, and kernel restrictions." ;;
                    *)
                        finding "MEDIUM" "capabilities.contextual.$cap" "A file holds context-dependent capability '$cap'" \
                            "Assess the binary's behavior and deployment context; this capability alone is not proof of root escalation." ;;
                esac
            fi
        done
    else
        skip_check "capabilities.scan" "File capability enumeration" "getcap not installed"
    fi
    return 0
}

# ============================== 15_check_cron.sh ==============================
# ------------------------------------------------------------------------------
# Check: cron / scheduled tasks
# ------------------------------------------------------------------------------

run_check_cron() {
    section "Scheduled Tasks (cron)"

    local found_any=0

    if have_readable /etc/crontab; then
        found_any=1
        finding "INFO" "cron.etc_crontab" "/etc/crontab contents" "$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' /etc/crontab 2>/dev/null)"
    fi

    for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
        if [ -d "$d" ]; then
            found_any=1
            local listing; listing="$(ls -la "$d" 2>/dev/null)"
            [ -n "$listing" ] && finding "INFO" "cron.dir.$(basename "$d")" "Contents of $d" "$listing"

            # Check directory and file writability using the current user's
            # effective access. The old -perm -0002-only scan missed group-
            # writable cron entries that the current user can actually modify.
            if command_exists find; then
                local dir_access dir_mode other_digit cron_file file_access file_mode
                escal8_effective_access "$d" w
                dir_access=$?
                if [ "$dir_access" -eq 0 ]; then
                    dir_mode="$(escal8_mode_digits "$d" 2>/dev/null)"
                    other_digit="${dir_mode:2:1}"
                    if [[ "$other_digit" =~ ^[0-7]$ ]] && (( (other_digit & 2) != 0 )); then
                        finding "CRITICAL" "cron.writable_dir.$(basename "$d")" "Cron directory is world-writable: $d" \
                            "Unprivileged users may be able to plant or replace scheduled jobs."
                    else
                        finding "HIGH" "cron.writable_dir.$(basename "$d")" "Cron directory is writable by the current user: $d" \
                            "Verify ownership, group membership, sticky-bit behavior, and which jobs are executed as root."
                    fi
                elif [ "$dir_access" -eq 2 ]; then
                    skip_check "cron.dir_access.$(basename "$d")" "$d writability" "could not determine effective write access"
                fi

                local cron_files="$ESCAL8_TMPDIR/cron_files_$(basename "$d").txt"
                find "$d" -maxdepth 1 -type f -print 2>/dev/null > "$cron_files"
                while IFS= read -r cron_file; do
                    [ -n "$cron_file" ] || continue
                    escal8_effective_access "$cron_file" w
                    file_access=$?
                    if [ "$file_access" -eq 0 ]; then
                        file_mode="$(escal8_mode_digits "$cron_file" 2>/dev/null)"
                        other_digit="${file_mode:2:1}"
                        if [[ "$other_digit" =~ ^[0-7]$ ]] && (( (other_digit & 2) != 0 )); then
                            finding "CRITICAL" "cron.writable_file.$(basename "$cron_file")" "Cron file is world-writable: $cron_file" \
                                "A world-writable scheduled job or cron definition can permit privilege escalation."
                        else
                            finding "HIGH" "cron.writable_file.$(basename "$cron_file")" "Cron file is writable by the current user: $cron_file" \
                                "Verify that this file is executed or parsed by a privileged scheduler."
                        fi
                    elif [ "$file_access" -eq 2 ]; then
                        skip_check "cron.file_access.$(basename "$cron_file")" "$cron_file writability" "could not determine effective write access"
                    fi
                done < "$cron_files"
            else
                skip_check "cron.writable" "$d cron permission review" "find not available"
            fi
        fi
    done

    if [ -d /var/spool/cron ] || [ -d /var/spool/cron/crontabs ]; then
        found_any=1
        local spool_dir="/var/spool/cron/crontabs"
        [ -d "$spool_dir" ] || spool_dir="/var/spool/cron"
        local listing; listing="$(ls -la "$spool_dir" 2>/dev/null)"
        [ -n "$listing" ] && finding "INFO" "cron.spool" "User crontab spool ($spool_dir)" "$listing"
    fi

    # Current user's own crontab, if crontab(1) exists.
    if command_exists crontab; then
        local mine; mine="$(crontab -l 2>/dev/null)"
        [ -n "$mine" ] && finding "INFO" "cron.mine" "Current user's crontab" "$mine"
    fi

    if [ "$found_any" -eq 0 ]; then
        skip_check "cron.all" "Cron enumeration" "no cron directories/files found or accessible"
    fi
    return 0
}

# ============================== 16_check_writable.sh ==============================
# ------------------------------------------------------------------------------
# Check: writable sensitive files and directories
# ------------------------------------------------------------------------------

_ESCAL8_SENSITIVE_FILES="/etc/passwd /etc/shadow /etc/sudoers /etc/crontab /etc/hosts /etc/ld.so.preload /etc/ld.so.conf"

run_check_writable() {
    section "Writable Sensitive Paths"

    # Root always passes a plain -w test (DAC bypass), which is expected -
    # root legitimately owns and can write these files. That's not a
    # misconfiguration, so use escal8_effective_access to ask the question
    # that actually matters: could a non-root, non-owning user write here?
    for f in $_ESCAL8_SENSITIVE_FILES; do
        [ -e "$f" ] || continue
        escal8_effective_access "$f" w
        case $? in
            0)
                finding "CRITICAL" "writable.file.$(basename "$f")" "$f is writable by unprivileged users" \
                    "Direct write access to this file can typically be leveraged to gain root."
                ;;
            2)
                skip_check "writable.file.$(basename "$f")" "$f writability" \
                    "running as root and 'stat' is unavailable, so the actual permission bits could not be inspected"
                ;;
        esac
    done

    # Writable systemd unit directories let an attacker plant a unit that
    # root (or systemd running as root) will later execute. Same root-vs-
    # unprivileged distinction as above.
    for d in /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system; do
        [ -d "$d" ] || continue
        escal8_effective_access "$d" w
        case $? in
            0)
                finding "HIGH" "writable.systemd_dir" "Writable (by unprivileged users) systemd unit directory: $d" \
                    "A malicious unit file placed here could run as root when triggered or on next boot."
                ;;
            2)
                skip_check "writable.systemd_dir" "$d writability" \
                    "running as root and 'stat' is unavailable, so the actual permission bits could not be inspected"
                ;;
        esac
    done

    # Find root-owned executables that the current non-root user can modify.
    # This complements the process-script check: a writable root-owned binary
    # is a potential escalation vector only if a privileged workflow executes it.
    # Do not run this check as root, because root's ordinary DAC bypass would
    # make every root-owned file appear writable.
    if ! command_exists find; then
        skip_check "writable.root_execs" "Root-owned writable executable scan" "find not available"
    elif escal8_is_root; then
        skip_check "writable.root_execs" "Root-owned writable executable scan" \
            "running as root; current-user writability is meaningful for non-root scans"
    else
        local root_exec_candidates="$ESCAL8_TMPDIR/root_writable_exec_candidates.txt"
        local root_exec_errors="$ESCAL8_TMPDIR/root_writable_exec_errors.txt"
        local scan_rc error_lines
        : > "$root_exec_candidates"
        : > "$root_exec_errors"

        if find / -xdev -type f -user root -perm -0100 \
            \( -perm -0020 -o -perm -0002 \) \
            ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" \
            -print > "$root_exec_candidates" 2> "$root_exec_errors"; then
            scan_rc=0
        else
            scan_rc=$?
        fi

        if [ "$scan_rc" -ne 0 ]; then
            error_lines="$(wc -l < "$root_exec_errors" 2>/dev/null)"
            error_lines="${error_lines//[[:space:]]/}"
            error_lines="${error_lines:-0}"
            if [ -s "$root_exec_candidates" ]; then
                finding "INFO" "writable.root_execs.partial" \
                    "Root-owned executable scan was partial" \
                    "find exited with status $scan_rc after discovering candidates; $error_lines diagnostic line(s) were recorded. Discovered candidates are still evaluated, but inaccessible paths may contain additional findings."
            else
                skip_check "writable.root_execs" "Root-owned writable executable scan" \
                    "find exited with status $scan_rc and discovered no candidates; $error_lines diagnostic line(s) were recorded"
            fi
        fi

        while IFS= read -r candidate; do
            [ -n "$candidate" ] || continue
            if [ -w "$candidate" ]; then
                finding "HIGH" "writable.root_exec" \
                    "Root-owned executable is writable by the current user: $candidate" \
                    "Potential escalation if a privileged service, scheduled task, or administrator executes it. Verify its actual execution path before treating it as exploitable."
            fi
        done < "$root_exec_candidates"
    fi

    # Writable directories on PATH are covered separately in check_path, but
    # we also scan for a handful of common writable-by-group-or-world temp
    # and service directories that scripts/services often trust blindly.
    if command_exists find; then
        local dirs="/opt /srv /var/www /var/backups"
        for d in $dirs; do
            [ -d "$d" ] || continue
            local w
            w="$(find "$d" -maxdepth 2 -perm -0002 -type d 2>/dev/null)"
            [ -n "$w" ] && finding "MEDIUM" "writable.dir.$(basename "$d")" "World-writable subdirectories under $d" "$w"
        done
    else
        skip_check "writable.dirs" "World-writable directory scan" "find not available"
    fi
    return 0
}

# ============================== 17_check_path.sh ==============================
# ------------------------------------------------------------------------------
# Check: PATH hijacking opportunities
# ------------------------------------------------------------------------------

run_check_path() {
    section "PATH Integrity"

    finding "INFO" "path.value" "Current PATH" "$PATH"

    local old_ifs="$IFS"
    IFS=':'
    local dir
    for dir in $PATH; do
        IFS="$old_ifs"
        [ -z "$dir" ] && {
            finding "HIGH" "path.empty_entry" "PATH contains an empty entry (resolves to current directory)" ""
            continue
        }
        if [ "$dir" = "." ]; then
            finding "HIGH" "path.dot" "PATH contains '.' (current working directory)" \
                "Running common commands from an attacker-writable directory could execute planted binaries."
            continue
        fi
        if [ -d "$dir" ]; then
            # PATH risk is about whether OTHER users can plant an executable,
            # not whether the account running Escal8 can write to its own
            # directory. In particular, [ -w ] is true for a user's own
            # ~/.local/bin even when it is mode 755. Check group/other write
            # bits instead, dereferencing symlinks via escal8_mode_digits.
            local mode_digits group_digit other_digit
            mode_digits="$(escal8_mode_digits "$dir")"
            if [ -z "$mode_digits" ]; then
                skip_check "path.writable" "'$dir' writability" \
                    "stat is unavailable or permissions could not be inspected"
                IFS=':'
                continue
            fi
            group_digit="${mode_digits:1:1}"
            other_digit="${mode_digits:2:1}"
            if [[ "$group_digit" =~ ^[0-7]$ && "$other_digit" =~ ^[0-7]$ ]] && \
               (( (group_digit & 2) != 0 || (other_digit & 2) != 0 )); then
                finding "CRITICAL" "path.writable" "PATH directory '$dir' is writable by unprivileged users" \
                    "The directory grants write permission to its owning group or to other users. Verify group membership and any privileged process that uses this PATH."
            fi
        fi
        IFS=':'
    done
    IFS="$old_ifs"
    return 0
}

# ============================== 18_check_network.sh ==============================
# ------------------------------------------------------------------------------
# Check: network interfaces and listening sockets
# ------------------------------------------------------------------------------

run_check_network() {
    section "Network"

    if command_exists ip; then
        finding "INFO" "network.interfaces" "Network interfaces (ip addr)" "$(run_safe ip -o addr show)"
    elif command_exists ifconfig; then
        finding "INFO" "network.interfaces" "Network interfaces (ifconfig)" "$(run_safe ifconfig -a)"
    else
        skip_check "network.interfaces" "Network interface listing" "neither ip nor ifconfig available"
    fi

    # Prefer ss, fall back to netstat, fall back to raw /proc/net parsing so
    # the check still works on minimal containers with neither tool.
    if command_exists ss; then
        finding "INFO" "network.listening" "Listening sockets (ss)" "$(run_safe ss -tulpn)"
    elif command_exists netstat; then
        finding "INFO" "network.listening" "Listening sockets (netstat)" "$(run_safe netstat -tulpn)"
    elif have_readable /proc/net/tcp; then
        # Avoid awk's strtonum(), which is a gawk extension and is NOT
        # available under mawk or busybox awk. Extract the hex port field
        # with awk (portable) and convert hex->decimal using a bash
        # built-in arithmetic context instead, which works everywhere bash
        # itself runs.
        local hexports ports="" hp
        hexports="$(awk 'NR>1 { split($2,a,":"); print a[2] }' /proc/net/tcp 2>/dev/null)"
        if [ -n "$hexports" ]; then
            while IFS= read -r hp; do
                [ -z "$hp" ] && continue
                ports="$ports $((16#$hp))"
            done <<EOF
$hexports
EOF
            ports="$(printf '%s\n' $ports | sort -nu)"
        fi
        if [ -n "$ports" ]; then
            finding "INFO" "network.listening" "Local ports in use (parsed from /proc/net/tcp, IPv4 only)" "$ports"
        else
            skip_check "network.listening" "Listening socket enumeration" "could not parse /proc/net/tcp"
        fi
    else
        skip_check "network.listening" "Listening socket enumeration" "no ss, netstat, or /proc/net/tcp available"
    fi

    if have_readable /etc/hosts; then
        finding "INFO" "network.hosts" "/etc/hosts contents" "$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' /etc/hosts 2>/dev/null)"
    fi

    if have_readable /etc/resolv.conf; then
        finding "INFO" "network.resolv" "DNS configuration" "$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' /etc/resolv.conf 2>/dev/null)"
    fi
    return 0
}

# ============================== 19_check_services.sh ==============================
# ------------------------------------------------------------------------------
# Check: running processes and services
# ------------------------------------------------------------------------------

run_check_services() {
    section "Processes & Services"

    if command_exists ps; then
        # -ef is POSIX-specified; avoid GNU-only `ps aux` style flags.
        local procs; procs="$(ps -ef 2>/dev/null)"
        if [ -n "$procs" ]; then
            finding "INFO" "services.processes" "Running processes (ps -ef)" "$procs"

            # Processes running as root that exec a script writable by the
            # CURRENT, non-root user are a classic escalation vector: the
            # whole point is "I am not root, but I can modify a file root
            # will execute." When Escal8 itself is running as root, that
            # question is moot - root can trivially write anything root
            # owns, which is not a vulnerability - so skip rather than
            # flag a tautology.
            if ! command_exists find; then
                skip_check "services.writable_root_script" "Root-owned script writable by current user" "find not available"
            elif escal8_is_root; then
                skip_check "services.writable_root_script" "Root-owned script writable by current user" \
                    "running as root - this check only identifies a real escalation path for a non-root user"
            else
                local root_procs
                root_procs="$(printf '%s\n' "$procs" | awk '$1=="root"')"
                # Use process substitution, not a pipeline into `while`:
                # finding() updates severity and per-check counters in shell
                # arrays. A pipeline loop runs in a subshell on Bash, so the
                # finding record may be written while summary counts and the
                # final exit code incorrectly remain clean.
                while IFS= read -r line; do
                    [ -n "$line" ] || continue
                    for tok in $line; do
                        case "$tok" in
                            /*.sh|/*.py|/*.pl|/*.rb)
                                if [ -e "$tok" ] && [ -w "$tok" ]; then
                                    finding "CRITICAL" "services.writable_root_script" \
                                        "Root process references a script writable by current user" "$line"
                                fi
                                ;;
                        esac
                    done
                done < <(printf '%s\n' "$root_procs")
            fi
        else
            skip_check "services.processes" "Process listing" "ps returned no output"
        fi
    else
        skip_check "services.processes" "Process listing" "ps not available"
    fi

    if command_exists systemctl; then
        finding "INFO" "services.systemd" "Active systemd services" \
            "$(run_safe systemctl list-units --type=service --state=running --no-legend --no-pager)"

        # Review literal absolute ExecStart targets from installed service
        # units. This does not execute or reload units; systemd expansions,
        # wrappers, and non-absolute command forms are deliberately not guessed.
        if command_exists find; then
            local unit_dirs="/etc/systemd/system /lib/systemd/system /usr/lib/systemd/system"
            local unit_dir unit_file exec_line exec_path parent_dir access
            local unit_list="$ESCAL8_TMPDIR/systemd_unit_files.txt"
            : > "$unit_list"
            for unit_dir in $unit_dirs; do
                [ -d "$unit_dir" ] || continue
                find "$unit_dir" -maxdepth 4 -type f -name '*.service' -print 2>/dev/null >> "$unit_list"
            done
            sort -u "$unit_list" -o "$unit_list" 2>/dev/null
            while IFS= read -r unit_file; do
                [ -r "$unit_file" ] || continue
                escal8_effective_access "$unit_file" w
                access=$?
                if [ "$access" -eq 0 ]; then
                    finding "HIGH" "services.writable_unit.$(basename "$unit_file")" \
                        "Systemd service unit is writable by the current user: $unit_file" \
                        "Changes to a privileged unit definition may be executed by systemd. Verify the unit's effective owner and activation path."
                fi
                while IFS= read -r exec_line; do
                    exec_path="$(printf '%s\n' "$exec_line" | sed -nE 's/^[[:space:]]*ExecStart[[:space:]]*=[[:space:]]*[-@:+!]*(\/[^[:space:];]+).*/\1/p')"
                    case "$exec_path" in /*) ;; *) continue ;; esac
                    if [ -f "$exec_path" ]; then
                        escal8_effective_access "$exec_path" w
                        access=$?
                        if [ "$access" -eq 0 ]; then
                            finding "HIGH" "services.writable_exec.$(basename "$exec_path")" \
                                "Systemd ExecStart target is writable by the current user: $exec_path" \
                                "This is a candidate only; confirm the unit runs with elevated privileges and the parsed executable path is correct."
                        fi
                    fi
                    parent_dir="${exec_path%/*}"
                    [ -n "$parent_dir" ] || parent_dir=/
                    if [ -d "$parent_dir" ]; then
                        escal8_effective_access "$parent_dir" w
                        access=$?
                        if [ "$access" -eq 0 ]; then
                            finding "HIGH" "services.writable_exec_dir.$(basename "$parent_dir")" \
                                "Systemd ExecStart parent directory is writable by the current user: $parent_dir" \
                                "A writable parent directory may permit replacing the executable; verify the exact unit and directory semantics."
                        fi
                    fi
                done <<EOF_EXEC_LINES
$(grep -E '^[[:space:]]*ExecStart[[:space:]]*=' "$unit_file" 2>/dev/null)
EOF_EXEC_LINES
            done < "$unit_list"
        else
            skip_check "services.systemd_exec" "Systemd ExecStart path review" "find not available"
        fi
    elif have_readable /etc/init.d; then
        finding "INFO" "services.initd" "init.d scripts present" "$(ls -la /etc/init.d 2>/dev/null)"
    else
        skip_check "services.manager" "Service manager enumeration" "systemctl not available and no /etc/init.d"
    fi
    return 0
}

# ============================== 20_check_containers.sh ==============================
# ------------------------------------------------------------------------------
# Check: container escape surface
# ------------------------------------------------------------------------------

run_check_containers() {
    section "Container Context"

    local in_container=0
    have_readable /.dockerenv && in_container=1
    if have_readable /proc/1/cgroup && grep -qE 'docker|lxc|kubepods' /proc/1/cgroup 2>/dev/null; then
        in_container=1
    fi

    if [ "$in_container" -eq 0 ]; then
        finding "OK" "containers.not_detected" "No container indicators found" ""
        return 0
    fi

    finding "MEDIUM" "containers.detected" "Running inside a container" ""

    # Mounted docker.sock inside the container is a well-known full escape.
    # Deliberately NOT using escal8_effective_access here: unlike host
    # sensitive files (where root is the expected, legitimate owner and a
    # plain -w test is a false positive), container processes very
    # commonly run AS root by design, and root-in-container having write
    # access to the host's docker.sock is itself the exploitable condition
    # - not a bypass of some other, more restrictive intended permission.
    # A plain -w test correctly models "can the process that's actually
    # running right now use this escape", which is what matters here.
    if [ -S /var/run/docker.sock ]; then
        if [ -w /var/run/docker.sock ]; then
            finding "CRITICAL" "containers.docker_sock" "docker.sock is mounted and writable inside the container" \
                "Access to the Docker socket typically allows spawning a privileged container to escape to the host."
        else
            finding "HIGH" "containers.docker_sock_ro" "docker.sock is mounted but not writable" ""
        fi
    fi

    # Overly permissive capabilities granted to the container itself.
    if have_readable /proc/self/status; then
        local capeff
        capeff="$(grep -m1 '^CapEff:' /proc/self/status 2>/dev/null | awk '{print $2}')"
        [ -n "$capeff" ] && finding "INFO" "containers.capeff" "Effective capability mask: $capeff" \
            "Decode with 'capsh --decode=$capeff' if capsh is available."
    fi

    # Privileged-container hint: full device access.
    if have_readable /dev && command_exists find; then
        local devcount
        devcount="$(find /dev -maxdepth 1 -type b 2>/dev/null | wc -l | tr -d ' ')"
        if [ -n "$devcount" ] && [ "$devcount" -gt 5 ] 2>/dev/null; then
            finding "MEDIUM" "containers.many_devices" "Unusually broad device access inside container ($devcount block devices in /dev)" \
                "May indicate a privileged container with host device access."
        fi
    fi
    return 0
}

# ============================== 21_check_nfs.sh ==============================
# ------------------------------------------------------------------------------
# Check: NFS exports (no_root_squash)
# ------------------------------------------------------------------------------

run_check_nfs() {
    section "NFS Exports"

    if have_readable /etc/exports; then
        local exports; exports="$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' /etc/exports 2>/dev/null)"
        if [ -n "$exports" ]; then
            finding "INFO" "nfs.exports" "/etc/exports contents" "$exports"
            if printf '%s' "$exports" | grep -q 'no_root_squash'; then
                finding "CRITICAL" "nfs.no_root_squash" "An NFS export uses no_root_squash" \
                    "A client mounting this export as root can create a SUID binary and execute it as root on this host."
            fi
        else
            finding "OK" "nfs.none" "/etc/exports present but empty/commented out" ""
        fi
    else
        skip_check "nfs.exports" "NFS export configuration" "/etc/exports not present or not readable"
    fi

    # Currently mounted NFS shares (relevant even without local export config).
    if have_readable /proc/mounts; then
        local mounted; mounted="$(grep ' nfs' /proc/mounts 2>/dev/null)"
        [ -n "$mounted" ] && finding "INFO" "nfs.mounted" "Currently mounted NFS shares" "$mounted"
    fi
    return 0
}

# ============================== 22_check_ssh.sh ==============================
# ------------------------------------------------------------------------------
# Check: SSH keys and daemon configuration
# ------------------------------------------------------------------------------

run_check_ssh() {
    section "SSH"

    local home_dir="${HOME:-}"
    if [ -z "$home_dir" ] && command_exists getent && command_exists awk; then
        home_dir="$(getent passwd "$(id -un 2>/dev/null)" 2>/dev/null | awk -F: '{print $6}')"
    fi

    if [ -n "$home_dir" ] && [ -d "$home_dir/.ssh" ]; then
        local listing; listing="$(ls -la "$home_dir/.ssh" 2>/dev/null)"
        [ -n "$listing" ] && finding "INFO" "ssh.user_dir" "$home_dir/.ssh contents" "$listing"

        for keyfile in "$home_dir"/.ssh/id_rsa "$home_dir"/.ssh/id_ed25519 "$home_dir"/.ssh/id_ecdsa "$home_dir"/.ssh/id_dsa; do
            [ -e "$keyfile" ] || continue
            escal8_effective_access "$keyfile" r
            case $? in
                0)
                    finding "HIGH" "ssh.private_key_readable" "Private SSH key is readable by an unprivileged user: $keyfile" \
                        "Could allow lateral movement if the key is used elsewhere with broader access. File contents are not included."
                    ;;
                2)
                    skip_check "ssh.private_key_access" "$keyfile readability" "could not determine effective access permissions"
                    ;;
            esac
        done

        if have_readable "$home_dir/.ssh/authorized_keys"; then
            finding "INFO" "ssh.authorized_keys" "authorized_keys present" "$(cat "$home_dir/.ssh/authorized_keys" 2>/dev/null)"
        fi
    else
        skip_check "ssh.user_dir" "User SSH directory enumeration" "no readable ~/.ssh directory found"
    fi

    if have_readable /etc/ssh/sshd_config; then
        local cfg
        cfg="$(grep -viE '^[[:space:]]*#|^[[:space:]]*$' /etc/ssh/sshd_config 2>/dev/null)"
        [ -n "$cfg" ] && finding "INFO" "ssh.sshd_config" "sshd_config (active directives)" "$cfg"

        if printf '%s' "$cfg" | grep -qiE '^[[:space:]]*PermitRootLogin[[:space:]]+yes'; then
            finding "MEDIUM" "ssh.permit_root_login" "sshd allows direct root login (PermitRootLogin yes)" ""
        fi
    else
        skip_check "ssh.sshd_config" "sshd configuration review" "/etc/ssh/sshd_config not readable"
    fi
    return 0
}

# ============================== 23_check_historyenv.sh ==============================
# ------------------------------------------------------------------------------
# Check: shell history and environment variables
# ------------------------------------------------------------------------------

_ESCAL8_SECRET_PATTERNS='(PASS|PASSWORD|SECRET|TOKEN|API_KEY|APIKEY|AWS_ACCESS|PRIVATE_KEY)'

run_check_historyenv() {
    section "History & Environment"

    local home_dir="${HOME:-}"
    for hf in "$home_dir/.bash_history" "$home_dir/.zsh_history" "$home_dir/.sh_history"; do
        if have_readable "$hf"; then
            local hits
            hits="$(grep -iE 'passw|secret|token|ssh |scp |sudo ' "$hf" 2>/dev/null | tail -n 20)"
            if [ -n "$hits" ]; then
                finding "MEDIUM" "historyenv.history_hits" "Potentially sensitive lines in $(basename "$hf")" "$hits"
            else
                finding "OK" "historyenv.history_clean" "$(basename "$hf") present, no obvious sensitive keywords in a quick scan" ""
            fi
        fi
    done

    # Scan current environment for variable names that often carry secrets.
    # We only ever inspect names/values already exposed to this process -
    # no escalation or cross-process access is attempted.
    local hits
    hits="$(env 2>/dev/null | grep -Ei "$_ESCAL8_SECRET_PATTERNS" | sed 's/=.*$/=<redacted>/')"
    if [ -n "$hits" ]; then
        finding "MEDIUM" "historyenv.env_secrets" "Environment variables with secret-like names" "$hits"
    else
        finding "OK" "historyenv.env_clean" "No obviously secret-named environment variables" ""
    fi
    return 0
}

# ============================== 24_check_kernel.sh ==============================
# ------------------------------------------------------------------------------
# Check: kernel version context
# ------------------------------------------------------------------------------
# Escal8 deliberately does NOT bundle or run any kernel exploit code or
# exploit-suggestion databases. It only surfaces the raw version information
# an assessor needs to manually cross-reference against a CVE database.

run_check_kernel() {
    section "Kernel Version Context"

    local kver
    kver="$(run_safe uname -r)"
    if [ -z "$kver" ]; then
        skip_check "kernel.version" "Kernel version" "uname not available"
        return 0
    fi

    finding "INFO" "kernel.version" "Kernel release: $kver" \
        "Cross-reference this version manually against a CVE database to identify applicable local privilege escalation advisories. Escal8 does not include or execute exploit code."

    if have_readable /proc/version; then
        finding "INFO" "kernel.proc_version" "/proc/version" "$(cat /proc/version 2>/dev/null)"
    fi

    # Whether the kernel was built with common hardening features, which
    # affects exploit reliability without implying a specific exploit.
    if have_readable /proc/sys/kernel/yama/ptrace_scope; then
        local yama; yama="$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null)"
        finding "INFO" "kernel.yama" "Yama ptrace_scope: $yama" \
            "0 permits broader ptrace use, which can aid process-injection style techniques."
    fi

    if have_readable /proc/sys/kernel/kptr_restrict; then
        finding "INFO" "kernel.kptr_restrict" "kptr_restrict: $(cat /proc/sys/kernel/kptr_restrict 2>/dev/null)" ""
    fi
    return 0
}

# ============================== 25_check_processes.sh ==============================
# ------------------------------------------------------------------------------
# Check: privileged process executable/script paths
# ------------------------------------------------------------------------------

run_check_processes() {
    section "Privileged Process Paths"

    if escal8_is_root; then
        skip_check "processes.current_user_write" "Privileged process path writability" \
            "running as root; current-user writability is meaningful for non-root scans"
        return 0
    fi
    if [ ! -d /proc ] || ! command_exists ps; then
        skip_check "processes.proc" "Privileged process path review" \
            "procfs or ps is unavailable"
        return 0
    fi

    local listing line proc_user pid args exe cmdline checked=0 hits=0
    listing="$(ps -eo user=,pid=,args= 2>/dev/null)"
    if [ -z "$listing" ]; then
        skip_check "processes.list" "Privileged process listing" "ps returned no output"
        return 0
    fi

    while IFS= read -r line; do
        proc_user= pid= args=
        IFS=' ' read -r proc_user pid args <<EOF_PROC_LINE
$line
EOF_PROC_LINE
        [ "$proc_user" = root ] || continue
        case "$pid" in ''|*[!0-9]*) continue ;; esac
        checked=$((checked + 1))
        [ "$checked" -le 500 ] || break

        # /proc/PID/exe provides the actual executable, unlike argv[0].
        if command_exists readlink && [ -e "/proc/$pid/exe" ]; then
            exe="$(readlink "/proc/$pid/exe" 2>/dev/null)"
            exe="${exe% (deleted)}"
            if [ -n "$exe" ] && [ -f "$exe" ] && [ -w "$exe" ]; then
                finding "HIGH" "processes.root_exe_writable" \
                    "Root process executable is writable by the current user: $exe" \
                    "A privileged process is executing a file this user can modify. Verify the process lifecycle and file identity; the scanner does not modify or execute it."
                hits=$((hits + 1))
            fi
        fi

        # Command-line script paths catch common service wrappers. Treat argv
        # as evidence only; filenames with spaces or unusual quoting may not be
        # parsed perfectly, so the result is a candidate for manual review.
        if [ -r "/proc/$pid/cmdline" ]; then
            cmdline="$(tr '\000' ' ' < "/proc/$pid/cmdline" 2>/dev/null)"
            for exe in $cmdline; do
                case "$exe" in
                    /*.sh|/*.py|/*.pl|/*.rb|/*.php)
                        if [ -f "$exe" ] && [ -w "$exe" ]; then
                            finding "HIGH" "processes.root_script_writable" \
                                "Root process command line references a script writable by the current user: $exe" \
                                "Command-line parsing is heuristic. Confirm the process actually executes this path as root."
                            hits=$((hits + 1))
                        fi
                        ;;
                esac
            done
        fi
    done <<EOF_PROC_LIST
$listing
EOF_PROC_LIST

    if [ "$checked" -eq 0 ]; then
        skip_check "processes.root" "Root process path review" "no root-owned processes were visible in ps output"
    elif [ "$hits" -eq 0 ]; then
        finding "OK" "processes.root_paths_clean" "No writable executable/script paths found in sampled root processes" \
            "Reviewed up to 500 root process entries. Hidden processes and inaccessible procfs entries may limit coverage."
    fi
    return 0
}

# ============================== 26_check_credentials.sh ==============================
# ------------------------------------------------------------------------------
# Check: potentially sensitive files readable by the current user
# ------------------------------------------------------------------------------

run_check_credentials() {
    section "Potential Credential Files"

    if ! command_exists find; then
        skip_check "credentials.find" "Potential credential-file discovery" "find not available"
        return 0
    fi

    local scan_roots="/home /opt /srv /var/www /etc"
    local tmp="$ESCAL8_TMPDIR/credential_candidates.txt"
    : > "$tmp" 2>/dev/null || {
        skip_check "credentials.temp" "Potential credential-file discovery" "could not create candidate list"
        return 0
    }

    local rootdir
    for rootdir in $scan_roots; do
        [ -d "$rootdir" ] || continue
        find "$rootdir" -maxdepth 6 -type f \
            \( -name '.env' -o -name '.netrc' -o -name '.git-credentials' \
               -o -name 'credentials' -o -name 'credentials.json' \
               -o -name 'id_rsa' -o -name 'id_ed25519' -o -name 'id_ecdsa' \
               -o -name '*.kdbx' -o -name '*password*' -o -name '*secret*' \
               -o -name '*.pem' -o -name '*.p12' -o -name '*.pfx' \
               -o -name 'config.php' -o -name 'wp-config.php' \) \
            -print 2>/dev/null >> "$tmp"
    done

    local path count=0 shown=0 unknown=0 access candidates=''
    while IFS= read -r path; do
        [ -n "$path" ] || continue
        count=$((count + 1))
        # When running as root, do not confuse root's DAC bypass with a
        # credential file readable by an unprivileged account.
        escal8_effective_access "$path" r
        access=$?
        if [ "$access" -eq 2 ]; then
            unknown=$((unknown + 1))
            continue
        elif [ "$access" -ne 0 ]; then
            continue
        fi
        # Only report paths and metadata; never include secret file contents.
        if [ "$shown" -lt 200 ]; then
            candidates="${candidates}${path}"$'\n'
            shown=$((shown + 1))
        fi
    done < "$tmp"

    if [ "$shown" -gt 0 ]; then
        finding "MEDIUM" "credentials.readable_candidates" \
            "Potential credential/configuration files readable by the current user ($shown shown)" \
            "$candidates"
        if [ "$count" -gt 200 ]; then
            finding "INFO" "credentials.limit" "Credential candidate list truncated" \
                "More than 200 candidate paths were found; only the first 200 readable paths are shown."
        fi
    else
        finding "OK" "credentials.none" "No matching readable credential-file candidates found in scanned locations" \
            "Scanned existing directories among: $scan_roots (maximum depth 6). This is not a complete filesystem secret scan."
    fi
    if [ "$unknown" -gt 0 ]; then
        finding "INFO" "credentials.access_unknown" "Could not assess access to $unknown credential-file candidate(s)" \
            "Permission mode inspection was unavailable for some candidates; they were not treated as readable."
    fi
    return 0
}

# ============================== 27_check_acl.sh ==============================
# ------------------------------------------------------------------------------
# POSIX ACL review for privilege-sensitive paths (read-only)
# ------------------------------------------------------------------------------

# Return success only when a numeric ACL entry applies to the invoking UID or
# one of its supplementary groups AND its effective permissions include write.
# getfacl -e prints effective permissions when the ACL mask removes rights;
# getfacl -n avoids locale/name-resolution ambiguity. This prevents usernames
# containing "w" and masked-out write bits from producing false positives.
_escal8_acl_has_effective_write() {
    local acl_text="$1" uid="$2" groups="$3" owner_gid="$4"
    local line kind ident perms effective
    while IFS= read -r line; do
        [[ "$line" == user:*:* || "$line" == group:*:* ]] || continue
        kind="${line%%:*}"; line="${line#*:}"
        ident="${line%%:*}"; line="${line#*:}"
        perms="${line%%[[:space:]]*}"
        effective="$perms"
        if [[ "$line" == *'#effective:'* ]]; then
            effective="${line#*#effective:}"
            effective="${effective%%[[:space:]]*}"
        fi
        [[ "$effective" == *w* ]] || continue
        if [[ "$kind" == user && -n "$ident" && "$ident" == "$uid" ]]; then
            return 0
        fi
        if [[ "$kind" == group ]]; then
            if [[ -z "$ident" ]]; then
                [[ " $groups " == *" $owner_gid "* ]] && return 0
            elif [[ " $groups " == *" $ident "* ]]; then
                return 0
            fi
        fi
    done <<< "$acl_text"
    return 1
}

run_check_acl() {
    subsection "POSIX ACLs on privilege-sensitive paths"
    if ! command_exists getfacl; then
        finding SKIP "acl.getfacl_missing" "getfacl is unavailable; ACL-specific checks skipped" "Install the acl package on the audit workstation/target to enable this check."
        return 0
    fi
    local uid groups path owner acl owner_gid
    uid="$(id -u 2>/dev/null)"; groups=" $(id -G 2>/dev/null) "
    for path in /etc/passwd /etc/shadow /etc/sudoers /etc/crontab /etc/ld.so.preload /etc/ld.so.conf /etc/profile /etc/bash.bashrc /etc/ssh/sshd_config /usr/local/bin /usr/local/sbin /etc/cron.d /etc/systemd/system; do
        [ -e "$path" ] || continue
        owner="$(stat -Lc '%u' "$path" 2>/dev/null || stat -c '%u' "$path" 2>/dev/null)"
        [ "$owner" = "0" ] || continue
        owner_gid="$(stat -Lc '%g' "$path" 2>/dev/null || stat -c '%g' "$path" 2>/dev/null)"
        acl="$(getfacl -cpne -- "$path" 2>/dev/null)" || continue
        if _escal8_acl_has_effective_write "$acl" "$uid" "$groups" "$owner_gid"; then
            finding HIGH "acl.current_user_write.$(basename "$path")" "Effective ACL may grant the current user write access to a root-owned sensitive path" "$path (root-owned); effective ACL write entry detected. Review the full ACL and path semantics before concluding exploitability."
        fi
    done
    finding INFO "acl.review_scope" "ACL review completed for selected privilege-sensitive paths" "Only selected paths were inspected. This is not a filesystem-wide ACL inventory. ACL mask/effective rights and numeric IDs are considered."
}

# ============================== 28_check_sudotokens.sh ==============================
# ------------------------------------------------------------------------------
# Sudo timestamp / environment metadata (never dump token contents)
# ------------------------------------------------------------------------------
run_check_sudotokens() {
    subsection "Sudo timestamp and session metadata"
    local uid user dir f count=0
    uid="$(id -u 2>/dev/null)"; user="$(id -un 2>/dev/null)"
    # Environment variable NAMES only; values may contain secrets and are never printed.
    local envnames=""
    if [ -r "/proc/$$/environ" ]; then
        envnames="$(tr '\0' '\n' < "/proc/$$/environ" 2>/dev/null | cut -d= -f1 | grep -E '^(SUDO_|SSH_AUTH_SOCK$|SSH_AGENT_PID$)' | sort -u | tr '\n' ' ')"
    fi
    if [ -n "$envnames" ]; then
        finding INFO "sudo_tokens.environment_metadata" "Sudo/SSH session-related environment variable names are present" "$envnames (values intentionally redacted; presence alone is not a vulnerability)."
    else
        finding OK "sudo_tokens.no_env_metadata" "No common sudo/SSH agent environment names found in this process environment" "This does not prove that no cached sudo timestamp or agent socket exists."
    fi
    for dir in "/run/sudo/ts" "/var/run/sudo/ts"; do
        [ -d "$dir" ] || continue
        for f in "$dir"/*; do
            [ -e "$f" ] || continue
            count=$((count+1))
            # Report metadata only, never read timestamp file contents.
            finding INFO "sudo_tokens.timestamp_metadata" "Sudo timestamp metadata file exists" "$f; $(stat -c 'owner=%U mode=%a size=%s' "$f" 2>/dev/null || stat -f 'owner=%Su mode=%Lp size=%z' "$f" 2>/dev/null || echo 'metadata unavailable'). Existence is normal and is not proof of a reusable credential."
        done
    done
    [ "$count" -gt 0 ] || finding OK "sudo_tokens.no_timestamp_files" "No visible sudo timestamp files found in common locations" "Other sudo implementations or namespaces may store state elsewhere."
}

# ============================== 29_check_mounts.sh ==============================
# ------------------------------------------------------------------------------
# Mount options relevant to common privilege-escalation paths
# ------------------------------------------------------------------------------
run_check_mounts() {
    subsection "Mount options and temporary execution surfaces"
    local target fstype opts tool=0 assessed=0
    if command_exists findmnt; then
        tool=1
        while IFS=' ' read -r target fstype opts; do
            [ -n "$target" ] || continue
            assessed=$((assessed+1))
            case "$target" in
                /tmp|/var/tmp|/dev/shm|/run/shm)
                    if [[ ",$opts," == *,rw,* ]]; then
                        if [[ ",$opts," != *,noexec,* ]]; then
                            finding MEDIUM "mount.exec_writable_tmp.$(basename "$target")" "Temporary mount is writable and does not show noexec" "$target ($fstype; $opts). This increases the usefulness of a writable staging location but is not by itself a privilege escalation."
                        else
                            finding INFO "mount.noexec_tmp.$(basename "$target")" "Temporary mount is marked noexec" "$target ($fstype; $opts)"
                        fi
                    fi
                    ;;
            esac
            if [ "$target" = "/" ]; then
                [[ ",$opts," == *,rw,* ]] && finding INFO "mount.root_rw" "Root filesystem is mounted read-write" "$opts (normal on many live systems; interpret with other findings)."
            fi
        done < <(findmnt -rn -o TARGET,FSTYPE,OPTIONS 2>/dev/null | awk 'NF>=3 {print $1, $2, $3}')
    fi
    if [ "$tool" -eq 0 ]; then
        finding SKIP "mount.findmnt_missing" "findmnt is unavailable; structured mount-option review skipped" "A /proc/mounts fallback is intentionally not used here because escaping/field parsing differs across systems."
    else
        finding INFO "mount.review_scope" "Mount review inspected ${assessed} visible mount entries" "Checks focus on common temporary execution surfaces and the root mount, not every filesystem security policy."
    fi
    # Writable bind-mounted host paths / container context can alter interpretation.
    if [ -e /.dockerenv ] || grep -qaE '(docker|containerd|kubepods|lxc)' /proc/1/cgroup 2>/dev/null; then
        finding INFO "mount.container_context" "Container context detected; mount visibility may be namespace-limited" "Host mounts and host-side permissions may not be visible from this namespace."
    fi
}

# ============================== 30_check_software.sh ==============================
# ------------------------------------------------------------------------------
# Package-manager and development-tool inventory for follow-up version review
# ------------------------------------------------------------------------------
run_check_software() {
    subsection "Installed software and potentially relevant tool inventory"
    local os="unknown" count=0 pkg
    if [ -r /etc/os-release ]; then
        os="$(grep -E '^(ID|VERSION_ID|VERSION_CODENAME)=' /etc/os-release 2>/dev/null | tr '\n' ' ')"
    fi
    finding INFO "software.os_release" "Platform identity for version-specific follow-up" "$os"
    if command_exists dpkg-query; then
        local pkgs
        pkgs="$(dpkg-query -W -f='${binary:Package}\t${Version}\n' 2>/dev/null | grep -Ei '^(sudo|openssh-server|polkit|policykit|pkexec|docker|containerd|runc|podman|linux-image|linux-headers|apache2|nginx|mysql-server|mariadb-server|postgresql|redis-server|screen|tmux|vim|nano|perl|python3|ruby|php|nodejs|gcc|make)([^[:alnum:]_-]|$)' | head -n 80)"
        if [ -n "$pkgs" ]; then
            while IFS= read -r pkg; do
                [ -n "$pkg" ] || continue; count=$((count+1))
                finding INFO "software.package_inventory.$count" "Installed package candidate for manual version/CVE verification" "$pkg"
            done <<< "$pkgs"
        fi
    elif command_exists rpm; then
        while IFS= read -r pkg; do
            [ -n "$pkg" ] || continue; count=$((count+1))
            finding INFO "software.package_inventory.$count" "Installed package candidate for manual version/CVE verification" "$pkg"
        done < <(rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\n' 2>/dev/null | grep -Ei '^(sudo|openssh|polkit|docker|containerd|runc|podman|kernel|httpd|nginx|mariadb|postgresql|redis|screen|tmux|vim|perl|python|ruby|php|nodejs|gcc|make)([^[:alnum:]_-]|$)' | head -n 80)
    elif command_exists apk; then
        while IFS= read -r pkg; do
            [ -n "$pkg" ] || continue; count=$((count+1))
            finding INFO "software.package_inventory.$count" "Installed package candidate for manual version/CVE verification" "$pkg"
        done < <(apk info -v 2>/dev/null | grep -Ei '^(sudo|openssh|polkit|docker|containerd|runc|podman|linux|apache2|nginx|mariadb|postgresql|redis|screen|tmux|vim|perl|python|ruby|php|nodejs|gcc|make)([^[:alnum:]_-]|$)' | head -n 80)
    else
        finding SKIP "software.package_manager_missing" "No supported package query tool detected" "Tried dpkg-query, rpm, and apk."
    fi
    finding INFO "software.version_matching_limit" "Package inventory is not a vulnerability verdict" "Escal8 does not currently ship a maintained vendor-aware CVE database and does not infer vulnerability from version strings alone. Validate package versions against the distribution's security tracker, including backported fixes."
}

# ============================== 31_check_systemd_timers.sh ==============================
# ------------------------------------------------------------------------------
# Check: systemd timers and timer-triggered units
# ------------------------------------------------------------------------------
run_check_systemd_timers() {
    section "Systemd Timers"
    if ! command_exists systemctl; then
        skip_check "systemd_timers.systemctl_missing" "systemd timer enumeration" "systemctl unavailable"
        return 0
    fi

    local timers="$ESCAL8_TMPDIR/systemd_timers.txt" timer unit fragment execstart user access
    systemctl list-timers --all --no-legend --no-pager 2>/dev/null > "$timers"
    if [ ! -s "$timers" ]; then
        finding INFO "systemd_timers.none_visible" "No systemd timers were returned" "systemctl may be unavailable in a container, or no timers are configured."
        return 0
    fi
    finding INFO "systemd_timers.inventory" "Systemd timers visible to the current context" "$(head -n 100 "$timers")"

    # Resolve timer units to their associated service units without starting,
    # stopping, or reloading any service.
    while IFS= read -r timer; do
        [[ "$timer" == *.timer ]] || continue
        unit="${timer%.timer}.service"
        fragment="$(systemctl show "$unit" -p FragmentPath --value 2>/dev/null | head -n 1)"
        execstart="$(systemctl show "$unit" -p ExecStart --value 2>/dev/null | head -n 1)"
        user="$(systemctl show "$unit" -p User --value 2>/dev/null | head -n 1)"
        [ -n "$fragment" ] || continue
        if [ -f "$fragment" ]; then
            escal8_effective_access "$fragment" w; access=$?
            if [ "$access" -eq 0 ]; then
                finding HIGH "systemd_timers.writable_unit.$(basename "$unit")" "Timer-associated systemd unit is writable by the current user" "$fragment (unit=$unit, configured User=${user:-root/default}); verify activation and privilege context."
            fi
        fi
        # Extract a literal executable path only. systemd ExecStart syntax is
        # complex, so this intentionally reports candidates for manual review.
        local path
        path="$(printf '%s\n' "$execstart" | sed -nE 's/.*path=([^ ;}]+).*/\1/p' | head -n 1)"
        case "$path" in /*)
            if [ -f "$path" ]; then
                escal8_effective_access "$path" w; access=$?
                if [ "$access" -eq 0 ]; then
                    finding HIGH "systemd_timers.writable_exec.$(basename "$path")" "Timer-associated executable is writable by the current user" "$path (unit=$unit, configured User=${user:-root/default}); confirm the exact ExecStart semantics."
                fi
            fi
            ;;
        esac
    done < <(awk 'NF >= 5 {print $5}' "$timers")
    return 0
}

# ============================== 32_check_polkit.sh ==============================
# ------------------------------------------------------------------------------
# Check: polkit configuration and pkexec posture
# ------------------------------------------------------------------------------
run_check_polkit() {
    section "Polkit Configuration"
    local d f access count=0
    for d in /etc/polkit-1/rules.d /etc/polkit-1/localauthority /usr/share/polkit-1/rules.d /usr/share/polkit-1/actions; do
        [ -d "$d" ] || continue
        finding INFO "polkit.directory.$(basename "$d")" "Polkit configuration directory found" "$d"
        while IFS= read -r f; do
            [ -n "$f" ] || continue
            count=$((count + 1))
            if [ -f "$f" ]; then
                escal8_effective_access "$f" w; access=$?
                if [ "$access" -eq 0 ]; then
                    finding HIGH "polkit.writable_file.$(basename "$f")" "Polkit rule/action file is writable by the current user" "$f; validate whether the file is loaded and whether its rules grant privileged actions."
                fi
            fi
        done < <(find "$d" -maxdepth 2 -type f \( -name '*.rules' -o -name '*.pkla' -o -name '*.policy' \) -print 2>/dev/null)
    done
    if [ "$count" -eq 0 ]; then
        finding INFO "polkit.no_rules_found" "No polkit rule/action files found in standard directories" "This is not proof that polkit is absent; paths and distro packaging vary."
    fi
    if command_exists pkexec; then
        local mode owner
        mode="$(stat -Lc '%a' "$(command -v pkexec)" 2>/dev/null || stat -c '%a' "$(command -v pkexec)" 2>/dev/null)"
        owner="$(stat -Lc '%u' "$(command -v pkexec)" 2>/dev/null || stat -c '%u' "$(command -v pkexec)" 2>/dev/null)"
        finding INFO "polkit.pkexec_metadata" "pkexec binary metadata" "path=$(command -v pkexec), uid=${owner:-unknown}, mode=${mode:-unknown}; metadata alone does not establish vulnerability."
    else
        skip_check "polkit.pkexec_missing" "pkexec metadata" "pkexec unavailable"
    fi
    return 0
}

# ============================== 33_check_kernel_hardening.sh ==============================
# ------------------------------------------------------------------------------
# Check: kernel hardening posture (informational; not a CVE detector)
# ------------------------------------------------------------------------------
run_check_kernel_hardening() {
    section "Kernel Hardening Posture"
    local key path val
    local keys="kernel.randomize_va_space kernel.kptr_restrict kernel.dmesg_restrict kernel.yama.ptrace_scope kernel.unprivileged_bpf_disabled fs.protected_hardlinks fs.protected_symlinks fs.suid_dumpable"
    local readable=0
    for key in $keys; do
        path="/proc/sys/${key//./\/}"
        [ -r "$path" ] || continue
        val="$(cat "$path" 2>/dev/null)"
        [ -n "$val" ] || continue
        readable=$((readable + 1))
        case "$key:$val" in
            kernel.randomize_va_space:0)
                finding MEDIUM "hardening.$key" "Kernel ASLR appears disabled" "$key=$val. This weakens a defense; it is not by itself proof of a privilege-escalation path." ;;
            kernel.kptr_restrict:0)
                finding LOW "hardening.$key" "Kernel pointer restriction is disabled" "$key=$val. Impact depends on kernel, permissions, and other mitigations." ;;
            kernel.dmesg_restrict:0)
                finding LOW "hardening.$key" "Kernel log access restriction is disabled" "$key=$val. Check effective dmesg permissions and distribution defaults." ;;
            kernel.yama.ptrace_scope:0)
                finding MEDIUM "hardening.$key" "Yama ptrace restriction is permissive" "$key=$val. Exploitability depends on process ownership, capabilities, namespaces, and other controls." ;;
            kernel.unprivileged_bpf_disabled:0)
                finding LOW "hardening.$key" "Unprivileged BPF is not disabled by this sysctl" "$key=$val. Kernel configuration and other BPF controls also matter." ;;
            fs.suid_dumpable:2)
                finding LOW "hardening.$key" "SUID core-dump mode is set to 2" "$key=$val. Review core_pattern, dump handling, and local policy." ;;
        esac
    done
    if [ "$readable" -eq 0 ]; then
        skip_check "hardening.sysctl_unavailable" "Kernel hardening sysctl review" "no supported /proc/sys keys were readable"
    else
        finding INFO "hardening.scope" "Kernel hardening sysctls reviewed" "$readable settings read. This is a posture check, not a complete kernel configuration or CVE assessment."
    fi
    return 0
}

# ============================== 34_check_deleted_files.sh ==============================
# ------------------------------------------------------------------------------
# Check: deleted files still held open by processes
# ------------------------------------------------------------------------------
run_check_deleted_files() {
    section "Deleted Files Held Open"
    local out='' rc=0
    # When a fixture proc root is supplied, exercise that fixture directly;
    # host lsof output must not short-circuit the deterministic test path.
    if [ -z "${ESCAL8_PROC_ROOT:-}" ] && command_exists lsof; then
        out="$(lsof -nP +L1 2>/dev/null | head -n 100)"
        rc=$?
        if [ -n "$out" ]; then
            finding INFO "deleted_files.open" "Processes hold deleted files open" "$out"
            finding INFO "deleted_files.interpretation" "Deleted-open-file entries need manual triage" "This may indicate deleted logs, replaced executables, or ordinary temporary files. Escal8 does not infer privilege escalation from this alone."
            return 0
        fi
        # lsof may return no rows because of permission limits; fall through to
        # /proc metadata as a second, independent source.
    fi

    # Linux /proc fallback: read symlink targets only; never read file contents.
    # ESCAL8_PROC_ROOT is overridable solely to make fixture-based tests possible.
    local proc_root="${ESCAL8_PROC_ROOT:-/proc}" fd pid comm target shown=0 matches='' total=0
    if [ -d "$proc_root" ] && command_exists readlink; then
        for fd in "$proc_root"/[0-9]*/fd/*; do
            [ -L "$fd" ] || continue
            target="$(readlink -- "$fd" 2>/dev/null)" || continue
            case "$target" in
                *' (deleted)')
                    total=$((total + 1))
                    [ "$shown" -lt 100 ] || continue
                    pid="${fd#"$proc_root"/}"; pid="${pid%%/*}"
                    comm="$(cat "$proc_root/$pid/comm" 2>/dev/null | head -n 1)"
                    [ -n "$comm" ] || comm='unknown'
                    matches="${matches}pid=${pid} comm=${comm} fd=${fd##*/} target=${target}"$'\n'
                    shown=$((shown + 1))
                    ;;
            esac
        done
        if [ "$total" -gt 0 ]; then
            finding INFO "deleted_files.open" "Processes hold deleted files open ($total visible; $shown shown)" "$matches"
            finding INFO "deleted_files.interpretation" "Deleted-open-file entries need manual triage" "Only visible /proc file-descriptor symlink metadata was inspected. Escal8 did not read file contents; process visibility depends on procfs mount options and privileges."
            [ "$total" -le 100 ] || finding INFO "deleted_files.truncated" "Deleted-open-file listing truncated" "Showing at most 100 visible file descriptors."
            return 0
        fi
        finding INFO "deleted_files.none_visible" "No deleted-open files were visible via lsof or /proc" "Absence is not proof of complete visibility; procfs restrictions, namespaces, and permissions may hide descriptors."
        return 0
    fi
    skip_check "deleted_files.unavailable" "Deleted-open-file enumeration" "lsof is unavailable and /proc file-descriptor metadata cannot be inspected"
    return 0
}

# ============================== 35_check_cloud.sh ==============================
# ------------------------------------------------------------------------------
# Check: cloud credentials and workload identity metadata (never reads secrets)
# ------------------------------------------------------------------------------

run_check_cloud() {
    section "Cloud Identity and Configuration"

    local env_names='' name present=0
    for name in AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_PROFILE \
                AWS_WEB_IDENTITY_TOKEN_FILE AWS_ROLE_ARN AWS_CONTAINER_CREDENTIALS_RELATIVE_URI \
                AWS_CONTAINER_CREDENTIALS_FULL_URI AZURE_CLIENT_ID AZURE_TENANT_ID \
                AZURE_CLIENT_SECRET AZURE_FEDERATED_TOKEN_FILE GOOGLE_APPLICATION_CREDENTIALS \
                CLOUDSDK_CONFIG GOOGLE_CLOUD_PROJECT GCP_PROJECT ARM_CLIENT_ID ARM_CLIENT_SECRET \
                ARM_TENANT_ID KUBECONFIG; do
        if printenv "$name" >/dev/null 2>&1; then
            env_names="${env_names}${name}, "
            present=1
        fi
    done
    if [ "$present" -eq 1 ]; then
        finding "INFO" "cloud.identity_env_names" "Cloud/workload identity environment variables are present" \
            "Names only: ${env_names%, }. Values are deliberately not collected or printed. Presence alone does not establish access or exposure."
    else
        finding "OK" "cloud.no_identity_env_names" "No common cloud identity environment variable names found" \
            "This does not rule out instance metadata identities, credential files, SDK defaults, or other provider-specific mechanisms."
    fi

    local homes='' home_dir path count=0 shown=0 candidates=''
    if [ -n "${HOME:-}" ] && [ -d "$HOME" ]; then homes="$HOME"; fi
    if [ -r /etc/passwd ]; then
        while IFS=: read -r _ _ uid _ _ h _; do
            case "$uid:$h" in
                [0-9]*:/*) [ -d "$h" ] && homes="${homes}${homes:+$'\n'}$h" ;;
            esac
        done < /etc/passwd
    fi

    # Inspect path metadata only; never cat, source, parse, or upload credential files.
    while IFS= read -r home_dir; do
        [ -n "$home_dir" ] || continue
        for path in \
            "$home_dir/.aws/credentials" "$home_dir/.aws/config" \
            "$home_dir/.azure/accessTokens.json" "$home_dir/.azure/azureProfile.json" \
            "$home_dir/.config/gcloud/application_default_credentials.json" \
            "$home_dir/.config/gcloud/credentials.db" "$home_dir/.kube/config" \
            "$home_dir/.docker/config.json" "$home_dir/.config/containers/auth.json" \
            "$home_dir/.terraform.d/credentials.tfrc.json" "$home_dir/.config/gh/hosts.yml"; do
            [ -f "$path" ] || continue
            count=$((count + 1))
            local mode owner last_digit
            mode="$(stat -Lc '%a' "$path" 2>/dev/null || stat -f '%Lp' "$path" 2>/dev/null)"
            owner="$(stat -Lc '%U' "$path" 2>/dev/null || stat -f '%Su' "$path" 2>/dev/null)"
            [ -n "$mode" ] || mode='unknown'
            [ -n "$owner" ] || owner='unknown'
            if [ "$shown" -lt 100 ]; then
                candidates="${candidates}${path} (owner=${owner}, mode=${mode})"$'\n'
                shown=$((shown + 1))
            fi
            # Flag only clearly world-readable sensitive files; do not infer that
            # a file is vulnerable merely because the current account can read it.
            case "$mode" in
                *[0-7])
                    last_digit="${mode: -1}"
                    if [ "$last_digit" != 'unknown' ] && [ $((10#$last_digit & 4)) -ne 0 ]; then
                        case "$path" in
                            */.aws/config|*/.azure/azureProfile.json)
                                # These files may contain account/profile metadata but are not
                                # inherently credential-bearing; report the path as INFO only.
                                ;;
                            *)
                                finding "HIGH" "cloud.world_readable_config" "Cloud/deployment credential configuration is world-readable: $path" \
                                    "Metadata only. Confirm the file contains sensitive material and inspect the provider's identity/credential scope; Escal8 did not read its contents."
                                ;;
                        esac
                    fi
                    ;;
            esac
        done
    done <<EOF_HOMES
$(printf '%s\n' "$homes" | sort -u)
EOF_HOMES

    if [ "$shown" -gt 0 ]; then
        finding "INFO" "cloud.config_paths" "Cloud and deployment configuration paths found ($shown shown)" \
            "$candidates"
        [ "$count" -le 100 ] || finding "INFO" "cloud.config_paths_truncated" "Cloud configuration path listing truncated" "More than 100 paths matched. No file contents were read."
    else
        finding "OK" "cloud.config_paths_none" "No common cloud configuration paths found in enumerated home directories" \
            "Path list is intentionally bounded and does not cover every SDK, container, or workload identity location."
    fi
    return 0
}

# ============================== 36_check_devops.sh ==============================
# ------------------------------------------------------------------------------
# Check: DevOps and orchestration control surfaces (metadata only)
# ------------------------------------------------------------------------------

run_check_devops() {
    section "DevOps and Orchestration Surfaces"

    local path owner mode desc count=0 output=''
    local candidates='/var/run/docker.sock /run/containerd/containerd.sock /run/podman/podman.sock /var/run/podman/podman.sock /etc/kubernetes/admin.conf /etc/kubernetes/kubelet.conf /var/lib/kubelet/config.yaml /etc/rancher/k3s/k3s.yaml /etc/rancher/rke2/rke2.yaml /var/lib/rancher/k3s/server/node-token /etc/containers/registries.conf /etc/gitlab-runner/config.toml /etc/jenkins/jenkins.model.JenkinsLocationConfiguration.xml'

    for path in $candidates; do
        [ -e "$path" ] || [ -S "$path" ] || continue
        count=$((count + 1))
        owner="$(stat -Lc '%U' "$path" 2>/dev/null || stat -f '%Su' "$path" 2>/dev/null)"
        mode="$(stat -Lc '%a' "$path" 2>/dev/null || stat -f '%Lp' "$path" 2>/dev/null)"
        [ -n "$owner" ] || owner='unknown'
        [ -n "$mode" ] || mode='unknown'
        output="${output}${path} (owner=${owner}, mode=${mode})"$'\n'
        if [ -S "$path" ] && [ -w "$path" ]; then
            finding "HIGH" "devops.writable_control_socket" "Current user can write to a container/runtime control socket: $path" \
                "A writable control socket may confer broad host or workload control. Confirm the socket's daemon, namespace, and authorization policy; Escal8 did not send commands to it."
        elif [ -f "$path" ]; then
            case "$mode" in
                *[0-7])
                    last_digit="${mode: -1}"
                    if [ $((10#$last_digit & 4)) -ne 0 ]; then
                        finding "HIGH" "devops.world_readable_control_config" "Orchestration/control configuration is world-readable: $path" \
                            "Metadata only. Confirm whether this file contains credentials or privileged cluster configuration; contents were not read."
                    fi
                    ;;
            esac
        fi
    done

    if [ "$count" -gt 0 ]; then
        finding "INFO" "devops.control_surfaces" "DevOps/orchestration control-surface paths found ($count)" "$output"
    else
        finding "OK" "devops.no_control_surfaces" "No common DevOps/orchestration control-surface paths found" \
            "This bounded list is not a complete inventory of runtimes, clusters, CI agents, or custom installations."
    fi

    # Report membership names only; group membership can be useful context but
    # does not by itself prove that a daemon socket is accessible.
    if command_exists id; then
        local groups
        groups="$(id -nG 2>/dev/null)"
        if printf ' %s ' "$groups" | grep -Eq ' (docker|lxd|libvirt|kvm|incus|podman) '; then
            finding "MEDIUM" "devops.runtime_groups" "User belongs to a group associated with container/VM management" \
                "Groups: $groups. Effective control depends on host policy, device/socket permissions, daemon configuration, and namespace boundaries."
        fi
    fi
    return 0
}

# ============================== 37_check_system_surfaces.sh ==============================
# ------------------------------------------------------------------------------
# Check: Linux startup, network-policy and local hardening surfaces
# ------------------------------------------------------------------------------
# Read-only inventory. This check intentionally does not dump firewall rules,
# PAM contents, or service configuration contents into reports. It reports
# metadata and narrowly scoped writable startup hooks instead.
run_check_system_surfaces() {
    subsection "Startup hooks, network policy and system hardening surfaces"
    local p access mode found=0 tool_out item

    # Loader configuration and shell/init hooks can affect privileged process
    # startup. Only report effective write access, not root's DAC bypass.
    for p in /etc/ld.so.preload /etc/ld.so.conf /etc/profile /etc/bash.bashrc \
             /etc/profile.d /etc/init.d /etc/rc.local /etc/inetd.conf \
             /etc/inetd.d /etc/sudoers.d; do
        [ -e "$p" ] || continue
        access="$(escal8_effective_access "$p" w; printf '%s' "$?")"
        case "$access" in
            0) finding "HIGH" "system_surfaces.writable_startup.$(printf '%s' "$p" | tr '/ .' '___')" \
                   "Current user can write a sensitive startup/configuration path: $p" \
                   "Potentially security-relevant write access. Confirm ownership, ACLs, service context and whether the path is consumed by privileged processes; no file contents were read." ; found=$((found+1)) ;;
            2) finding "SKIP" "system_surfaces.access_unknown.$(printf '%s' "$p" | tr '/ .' '___')" \
                   "Could not determine effective write access for $p" "Permission metadata or a required utility was unavailable." ;;
        esac
    done

    # Report the presence and state of network policy tools without printing
    # complete rulesets, which may be very large or contain sensitive topology.
    if command_exists nft; then
        tool_out="$(nft list tables 2>/dev/null | head -n 30)"
        if [ -n "$tool_out" ]; then
            finding "INFO" "system_surfaces.nftables" "nftables tables are configured" \
                "Table inventory only (first 30 lines): $(printf '%s' "$tool_out" | tr '\n' ';'). Rules were not dumped." 
        else
            finding "INFO" "system_surfaces.nftables" "nftables command is present; table inventory was empty or unavailable" \
                "This does not establish whether traffic filtering is effective." 
        fi
    elif command_exists iptables; then
        tool_out="$(iptables -S 2>/dev/null | head -n 1)"
        if [ -n "$tool_out" ]; then
            finding "INFO" "system_surfaces.iptables" "iptables is available" \
                "Rule listing is intentionally not included in the report. First policy line: $tool_out"
        else
            finding "INFO" "system_surfaces.iptables" "iptables is available but rules could not be enumerated" \
                "Permission, backend or namespace restrictions may apply." 
        fi
    else
        finding "SKIP" "system_surfaces.firewall_tools" "No nft or iptables command found" \
            "Firewall policy may be managed by another tool or outside this namespace." 
    fi

    # Firewall service status: status is evidence, not a security verdict.
    if command_exists systemctl; then
        for item in firewalld ufw nftables; do
            tool_out="$(systemctl is-active "$item" 2>/dev/null | head -n 1)"
            [ -n "$tool_out" ] || tool_out="unknown/inaccessible"
            finding "INFO" "system_surfaces.firewall_service.$item" "$item service state: $tool_out" \
                "Service state alone does not prove that effective filtering is configured." 
        done
    fi

    # Inventory common compilers/interpreters that can be relevant during
    # authorized post-compromise review. Presence is informational only.
    local tools="gcc cc clang make perl python3 python ruby php node go rustc"
    local present="" t
    for t in $tools; do
        if command_exists "$t"; then present="${present}${t} "; fi
    done
    if [ -n "$present" ]; then
        finding "INFO" "system_surfaces.development_tools" "Development tools available on PATH" \
            "${present% } . Presence is inventory, not evidence of a vulnerability."
    else
        finding "INFO" "system_surfaces.development_tools" "No common development tools found on PATH" \
            "Only the current PATH was checked; tools may exist elsewhere." 
    fi

    # Report selected non-secret hardening settings without exposing PAM files.
    if [ -r /etc/login.defs ]; then
        local setting value
        for setting in PASS_MAX_DAYS PASS_MIN_DAYS PASS_WARN_AGE UMASK; do
            value="$(awk -v key="$setting" '$1 == key && $1 !~ /^#/ {print $2; exit}' /etc/login.defs 2>/dev/null)"
            [ -n "$value" ] || value="unset"
            finding "INFO" "system_surfaces.login_defs.$setting" "login.defs $setting: $value" \
                "Informational policy metadata; PAM and distribution defaults may override or supplement it." 
        done
    else
        skip_check "system_surfaces.login_defs" "Selected login policy metadata" " /etc/login.defs is not readable or does not exist"
    fi

    # Loaded kernel modules and module signature enforcement are inventory /
    # hardening context only. Never claim a loaded module is exploitable.
    if command_exists lsmod; then
        local module_count
        module_count="$(lsmod 2>/dev/null | awk 'NR>1 {n++} END {print n+0}')"
        finding "INFO" "system_surfaces.loaded_modules" "Loaded kernel module count: ${module_count:-unknown}" \
            "Count only; module names and parameters are not dumped in this check." 
    else
        skip_check "system_surfaces.loaded_modules" "Loaded kernel module inventory" "lsmod is unavailable"
    fi
    if [ -r /sys/module/module/parameters/sig_enforce ]; then
        value="$(cat /sys/module/module/parameters/sig_enforce 2>/dev/null)"
        finding "INFO" "system_surfaces.module_signature_enforcement" "Kernel module signature enforcement: ${value:-unknown}" \
            "Kernel-specific setting; interpret with kernel configuration and distribution policy." 
    fi

    [ "$found" -gt 0 ] || finding "OK" "system_surfaces.startup_hooks" "No writable sensitive startup/configuration paths detected in the selected list" \
        "This is a bounded path check, not a complete filesystem or ACL audit." 
}

# ============================== 90_report.sh ==============================
# ------------------------------------------------------------------------------
# Summary + report generation
# ------------------------------------------------------------------------------

escal8_print_summary() {
    printf '\n%s=== Escal8 Summary ===%s\n' "${C_BOLD}${C_MAGENTA}" "$C_RESET"
    local sev
    for sev in CRITICAL HIGH MEDIUM LOW INFO OK SKIP FAILED; do
        local n="${ESCAL8_COUNTS[$sev]:-0}"
        local color; color="$(_escal8_sev_color "$sev")"
        printf '  %s%-8s%s : %s\n' "$color" "$sev" "$C_RESET" "$n"
    done

    local crit="${ESCAL8_COUNTS[CRITICAL]:-0}" high="${ESCAL8_COUNTS[HIGH]:-0}"
    if [ "$crit" -gt 0 ]; then
        printf '\n%s[!] %s CRITICAL finding(s) require immediate review.%s\n' "$C_RED$C_BOLD" "$crit" "$C_RESET"
    elif [ "$high" -gt 0 ]; then
        printf '\n%s[!] %s HIGH severity finding(s) worth reviewing.%s\n' "$C_YELLOW$C_BOLD" "$high" "$C_RESET"
    else
        printf '\n%s[+] No CRITICAL or HIGH severity findings in this run.%s\n' "$C_GREEN" "$C_RESET"
    fi
}

# escal8_print_check_coverage
# Prints which checks were completed, skipped (ran, but nothing could
# actually be assessed - every sub-item hit a missing tool), failed (an
# Escal8 bug, not a target finding), or simply not requested this run.
escal8_print_check_coverage() {
    [ "$ESCAL8_QUIET" -eq 1 ] && return 0
    printf '\n%s=== Check Coverage ===%s\n' "${C_BOLD}${C_MAGENTA}" "$C_RESET"

    local status label color c list
    for status in completed skipped failed unrequested; do
        case "$status" in
            completed)   label="Completed  "; color="$C_GREEN" ;;
            skipped)     label="Skipped    "; color="$C_DIM" ;;
            failed)      label="Failed     "; color="${C_MAGENTA}${C_BOLD}" ;;
            unrequested) label="Unrequested"; color="$C_DIM" ;;
        esac
        list=""
        for c in $ESCAL8_ALL_CHECKS; do
            [ "${ESCAL8_CHECK_STATUS[$c]:-unrequested}" = "$status" ] && list="$list $c"
        done
        list="$(printf '%s' "$list" | sed 's/^ //')"
        printf '  %s%s%s : %s\n' "$color" "$label" "$C_RESET" "${list:-(none)}"
    done
}

# _escal8_json_escape STRING
# Produces a JSON-string-safe version of STRING: escapes backslash and
# double-quote (structurally required), the named short escapes JSON
# defines for newline/CR/tab/backspace/form-feed, and any other control
# character (0x00-0x1F) as \u00XX, which the JSON spec requires - raw
# control bytes are not legal inside a JSON string. Pure bash, no awk/sed
# dependency, so it behaves identically regardless of which awk/sed happen
# to be on the target.
#
# Implementation note: the five named-escape substitutions below are plain
# O(1) bash parameter expansions, which is fast and sufficient for the
# overwhelming majority of finding text (paths, command output, config
# lines - none of which normally contain other control bytes). Order
# matters: backslash must be escaped FIRST, or the backslashes this
# function itself inserts for the other escapes would get double-escaped.
# A byte-by-byte scan (needed for arbitrary other control characters, e.g.
# a literal \x07 BEL byte some tool's output might contain) only runs if
# [[:cntrl:]] still matches after the cheap substitutions, so the common
# case never pays for it.
_escal8_json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    s="${s//$'\b'/\\b}"
    s="${s//$'\f'/\\f}"

    if [[ "$s" =~ [[:cntrl:]] ]]; then
        local out="" i c ord len
        local LC_ALL=C LC_CTYPE=C
        len=${#s}
        for (( i = 0; i < len; i++ )); do
            c="${s:i:1}"
            if [[ "$c" =~ [[:cntrl:]] ]]; then
                printf -v ord '%d' "'$c"
                out+="$(printf '\\u%04x' "$ord")"
            else
                out+="$c"
            fi
        done
        s="$out"
    fi

    printf '%s' "$s"
}

escal8_write_json() {
    local out="$1"
    {
        printf '{\n'
        printf '  "tool": "%s",\n' "$ESCAL8_NAME"
        printf '  "version": "%s",\n' "$ESCAL8_VERSION"
        printf '  "generated_at": "%s",\n' "$(human_time)"
        printf '  "profile": "%s",\n' "$ESCAL8_PROFILE"
        printf '  "counts": {\n'
        local first=1 sev
        for sev in CRITICAL HIGH MEDIUM LOW INFO OK SKIP FAILED; do
            [ "$first" -eq 1 ] || printf ',\n'
            first=0
            printf '    "%s": %s' "$sev" "${ESCAL8_COUNTS[$sev]:-0}"
        done
        printf '\n  },\n'
        printf '  "checks": {\n'
        local status c
        first=1
        for status in completed skipped failed unrequested; do
            [ "$first" -eq 1 ] || printf ',\n'
            first=0
            printf '    "%s": [' "$status"
            local first2=1
            for c in $ESCAL8_ALL_CHECKS; do
                [ "${ESCAL8_CHECK_STATUS[$c]:-unrequested}" = "$status" ] || continue
                [ "$first2" -eq 1 ] || printf ', '
                first2=0
                printf '"%s"' "$(_escal8_json_escape "$c")"
            done
            printf ']'
        done
        printf '\n  },\n'
        printf '  "findings": [\n'
        first=1
        while IFS='|' read -r sev id title detail; do
            [ -z "$sev" ] && continue
            [ "$first" -eq 1 ] || printf ',\n'
            first=0
            local dec; dec="$(_escal8_decode "$detail")"
            printf '    {"severity": "%s", "id": "%s", "title": "%s", "detail": "%s"}' \
                "$(_escal8_json_escape "$sev")" "$(_escal8_json_escape "$id")" \
                "$(_escal8_json_escape "$title")" "$(_escal8_json_escape "$dec")"
        done < "$ESCAL8_FINDINGS_FILE"
        printf '\n  ]\n'
        printf '}\n'
    } > "$out"
}

# _escal8_html_escape STRING
_escal8_html_escape() {
    printf '%s' "$1" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'
}

escal8_write_html() {
    local out="$1"
    {
        cat <<'HTMLHEAD'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Escal8 Report</title>
<style>
body{font-family:Consolas,Menlo,monospace;background:#111;color:#ddd;margin:2rem}
h1{color:#8ab4f8}
table{border-collapse:collapse;width:100%}
td,th{border:1px solid #333;padding:6px 10px;text-align:left;vertical-align:top}
th{background:#222}
.CRITICAL{background:#7a0000;color:#fff}
.HIGH{background:#5a2d00;color:#fff}
.MEDIUM{background:#5a4e00;color:#fff}
.LOW{color:#6cf}
.INFO{color:#8ab4f8}
.OK{color:#6c6}
.SKIP{color:#777}
.FAILED{background:#4a1a6a;color:#fff}
pre{white-space:pre-wrap;margin:0;font-size:0.9em}
</style>
</head>
<body>
HTMLHEAD
        printf '<h1>Escal8 v%s Report</h1>\n' "$ESCAL8_VERSION"
        printf '<p>Generated: %s &mdash; Profile: %s</p>\n' "$(human_time)" "$ESCAL8_PROFILE"

        printf '<h2>Check Coverage</h2>\n<ul>\n'
        local status c list
        for status in completed skipped failed unrequested; do
            list=""
            for c in $ESCAL8_ALL_CHECKS; do
                [ "${ESCAL8_CHECK_STATUS[$c]:-unrequested}" = "$status" ] && list="$list $c"
            done
            list="$(printf '%s' "$list" | sed 's/^ //')"
            printf '<li><b>%s</b>: %s</li>\n' "$(_escal8_html_escape "$status")" "$(_escal8_html_escape "${list:-(none)}")"
        done
        printf '</ul>\n'

        printf '<h2>Findings</h2>\n'
        printf '<table>\n<tr><th>Severity</th><th>Check ID</th><th>Title</th><th>Detail</th></tr>\n'
        while IFS='|' read -r sev id title detail; do
            [ -z "$sev" ] && continue
            local dec; dec="$(_escal8_decode "$detail")"
            printf '<tr class="%s"><td>%s</td><td>%s</td><td>%s</td><td><pre>%s</pre></td></tr>\n' \
                "$(_escal8_html_escape "$sev")" "$(_escal8_html_escape "$sev")" \
                "$(_escal8_html_escape "$id")" "$(_escal8_html_escape "$title")" \
                "$(_escal8_html_escape "$dec")"
        done < "$ESCAL8_FINDINGS_FILE"
        printf '</table>\n</body>\n</html>\n'
    } > "$out"
}

escal8_write_text_report() {
    local out="$1"
    {
        printf '%s v%s report - generated %s\n' "$ESCAL8_NAME" "$ESCAL8_VERSION" "$(human_time)"
        printf 'Profile: %s\n\n' "$ESCAL8_PROFILE"

        printf 'Check coverage:\n'
        local status c list
        for status in completed skipped failed unrequested; do
            list=""
            for c in $ESCAL8_ALL_CHECKS; do
                [ "${ESCAL8_CHECK_STATUS[$c]:-unrequested}" = "$status" ] && list="$list $c"
            done
            list="$(printf '%s' "$list" | sed 's/^ //')"
            printf '  %-12s: %s\n' "$status" "${list:-(none)}"
        done
        printf '\n'

        while IFS='|' read -r sev id title detail; do
            [ -z "$sev" ] && continue
            local dec; dec="$(_escal8_decode "$detail")"
            printf '[%s] %s - %s\n' "$sev" "$id" "$title"
            if [ -n "$dec" ]; then
                printf '%s\n' "$dec" | sed 's/^/    /'
            fi
            printf '\n'
        done < "$ESCAL8_FINDINGS_FILE"
    } > "$out"
}

escal8_write_report() {
    [ -z "$ESCAL8_OUTFILE" ] && return 0
    case "$ESCAL8_FORMAT" in
        json) escal8_write_json "$ESCAL8_OUTFILE" ;;
        html) escal8_write_html "$ESCAL8_OUTFILE" ;;
        *)    escal8_write_text_report "$ESCAL8_OUTFILE" ;;
    esac
    if [ "$ESCAL8_QUIET" -eq 0 ]; then
        printf '\n%s[+] Report written to %s (%s)%s\n' "$C_GREEN" "$ESCAL8_OUTFILE" "$ESCAL8_FORMAT" "$C_RESET"
    fi
}

# ============================== 99_main.sh ==============================
# ------------------------------------------------------------------------------
# Main orchestration
# ------------------------------------------------------------------------------

escal8_print_banner() {
    [ "$ESCAL8_QUIET" -eq 1 ] && return 0
    printf '%s%s v%s%s - Linux Privilege Escalation Enumeration\n' "$C_BOLD$C_CYAN" "$ESCAL8_NAME" "$ESCAL8_VERSION" "$C_RESET"
    printf '%sRead-only enumeration only. Use only on systems you are authorized to test.%s\n' "$C_DIM" "$C_RESET"
    printf 'Started: %s | Profile: %s\n' "$(human_time)" "$ESCAL8_PROFILE"
}

# Dispatch table: check keyword -> function name. A plain case statement is
# used instead of indirect variable expansion so this works unmodified under
# older bash (no need for namerefs here).
_escal8_run_one_check() {
    case "$1" in
        system)       run_check_system ;;
        users)        run_check_users ;;
        sudo)         run_check_sudo ;;
        suid)         run_check_suid ;;
        capabilities) run_check_capabilities ;;
        cron)         run_check_cron ;;
        writable)     run_check_writable ;;
        path)         run_check_path ;;
        network)      run_check_network ;;
        services)     run_check_services ;;
        processes)    run_check_processes ;;
        containers)   run_check_containers ;;
        nfs)          run_check_nfs ;;
        ssh)          run_check_ssh ;;
        historyenv)   run_check_historyenv ;;
        credentials)  run_check_credentials ;;
        acl)          run_check_acl ;;
        sudotokens)   run_check_sudotokens ;;
        mounts)       run_check_mounts ;;
        software)     run_check_software ;;
        kernel)       run_check_kernel ;;
        systemd_timers) run_check_systemd_timers ;;
        polkit)       run_check_polkit ;;
        kernel_hardening) run_check_kernel_hardening ;;
        deleted_files) run_check_deleted_files ;;
        cloud) run_check_cloud ;;
        devops) run_check_devops ;;
        system_surfaces) run_check_system_surfaces ;;
        *)
            # Should be unreachable from the CLI: escal8_parse_args now
            # validates every --checks entry against ESCAL8_ALL_CHECKS
            # before anything runs (see src/03_args.sh), rejecting unknown
            # names with exit code 2. This remains purely as a defensive
            # fallback against a maintainer letting ESCAL8_ALL_CHECKS and
            # this dispatch table drift out of sync.
            printf 'Warning: unknown check "%s" ignored\n' "$1" >&2
            return 1
            ;;
    esac
}

# escal8_init_check_coverage
# Every check Escal8 knows about starts out "unrequested"; the dispatch
# loop below promotes each one actually selected for this run to
# "completed", "skipped", or "failed" as it executes. This lets the
# summary and JSON/HTML reports clearly distinguish "we looked and it's
# clean", "we looked but could assess nothing at all" (every sub-check
# inside it hit a missing tool), "this wasn't part of the requested
# profile/--checks list", and "this crashed unexpectedly" (an Escal8 bug,
# not a target finding) - four different things that all look identical
# if you only see "no CRITICAL findings for X".
escal8_init_check_coverage() {
    local c
    for c in $ESCAL8_ALL_CHECKS; do
        ESCAL8_CHECK_STATUS[$c]="unrequested"
    done
}

escal8_main() {
    escal8_parse_args "$@"
    _escal8_colors_init
    escal8_init_runtime
    trap escal8_cleanup_runtime EXIT INT TERM
    escal8_init_check_coverage

    escal8_print_banner

    local chk rc
    for chk in $ESCAL8_SELECTED_CHECKS; do
        _ESCAL8_CURRENT_CHECK="$chk"
        _escal8_run_one_check "$chk"
        rc=$?
        _ESCAL8_CURRENT_CHECK=""

        if [ "$rc" -ne 0 ]; then
            ESCAL8_CHECK_STATUS[$chk]="failed"
            finding "FAILED" "internal.check_failed.$chk" \
                "Check module '$chk' exited unexpectedly (internal error, exit code $rc)" \
                "This indicates a bug in Escal8 itself, not a target misconfiguration. Results from this check may be incomplete - please report this."
        elif [ "${ESCAL8_CHECK_NONSKIP[$chk]:-0}" -gt 0 ]; then
            ESCAL8_CHECK_STATUS[$chk]="completed"
        else
            ESCAL8_CHECK_STATUS[$chk]="skipped"
        fi
    done

    escal8_print_summary
    escal8_print_check_coverage
    escal8_write_report

    # Exit code reflects worst finding severity, useful for CI/automation:
    # 2 = CRITICAL present, 1 = HIGH present, 0 = otherwise.
    if [ "${ESCAL8_COUNTS[CRITICAL]:-0}" -gt 0 ]; then
        exit 2
    elif [ "${ESCAL8_COUNTS[HIGH]:-0}" -gt 0 ]; then
        exit 1
    fi
    exit 0
}

escal8_main "$@"
