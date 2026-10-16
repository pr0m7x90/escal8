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
