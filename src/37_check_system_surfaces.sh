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
