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
