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
