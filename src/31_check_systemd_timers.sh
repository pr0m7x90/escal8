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
