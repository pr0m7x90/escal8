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
