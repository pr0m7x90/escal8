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
