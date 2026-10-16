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
