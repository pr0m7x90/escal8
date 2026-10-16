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
