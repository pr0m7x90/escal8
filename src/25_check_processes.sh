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
