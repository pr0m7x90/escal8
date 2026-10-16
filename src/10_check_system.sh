# ------------------------------------------------------------------------------
# Check: system / OS fingerprinting
# ------------------------------------------------------------------------------

run_check_system() {
    section "System Information"

    local kernel arch hostname
    kernel="$(run_safe uname -a)"
    arch="$(run_safe uname -m)"
    hostname="$(run_safe hostname)"

    if [ -n "$kernel" ]; then
        finding "INFO" "system.kernel" "Kernel: $kernel" ""
    else
        skip_check "system.kernel" "Kernel version" "uname not available"
    fi

    [ -n "$hostname" ] && finding "INFO" "system.hostname" "Hostname: $hostname" ""

    if have_readable /etc/os-release; then
        local pretty
        pretty="$(grep -m1 '^PRETTY_NAME=' /etc/os-release 2>/dev/null | sed 's/^PRETTY_NAME=//' | tr -d '"')"
        [ -n "$pretty" ] && finding "INFO" "system.distro" "Distribution: $pretty" ""
    elif have_readable /etc/issue; then
        finding "INFO" "system.distro" "Distribution (from /etc/issue): $(head -n1 /etc/issue 2>/dev/null)" ""
    else
        skip_check "system.distro" "Distribution identification" "no /etc/os-release or /etc/issue"
    fi

    # CPU/arch context matters for exploit applicability (e.g. 32 vs 64-bit).
    [ -n "$arch" ] && finding "INFO" "system.arch" "Architecture: $arch" ""

    # Container / virtualization hints - affects which escalation paths apply.
    local container_hint=""
    if have_readable /.dockerenv; then
        container_hint="/.dockerenv present"
    elif have_readable /proc/1/cgroup && grep -qE 'docker|lxc|kubepods' /proc/1/cgroup 2>/dev/null; then
        container_hint="cgroup references docker/lxc/kubepods"
    fi
    if [ -n "$container_hint" ]; then
        finding "MEDIUM" "system.container" "Host appears to be a container" "$container_hint"
    else
        finding "OK" "system.container" "No obvious container indicators" ""
    fi

    # Uptime / boot time: an old uptime without reboot can indicate unpatched
    # kernel is still in use even after a vendor fix was installed.
    if command_exists uptime; then
        finding "INFO" "system.uptime" "Uptime: $(uptime 2>/dev/null)" ""
    else
        skip_check "system.uptime" "Uptime" "uptime not available"
    fi

    # Sudo/package manager hints about patch level, without assuming any
    # particular package manager exists.
    if command_exists dpkg; then
        finding "INFO" "system.pkgmgr" "Package manager: dpkg/apt detected" ""
    elif command_exists rpm; then
        finding "INFO" "system.pkgmgr" "Package manager: rpm detected" ""
    elif command_exists apk; then
        finding "INFO" "system.pkgmgr" "Package manager: apk (Alpine) detected" ""
    else
        skip_check "system.pkgmgr" "Package manager identification" "no known package manager found"
    fi
    return 0
}
