# ------------------------------------------------------------------------------
# Check: container escape surface
# ------------------------------------------------------------------------------

run_check_containers() {
    section "Container Context"

    local in_container=0
    have_readable /.dockerenv && in_container=1
    if have_readable /proc/1/cgroup && grep -qE 'docker|lxc|kubepods' /proc/1/cgroup 2>/dev/null; then
        in_container=1
    fi

    if [ "$in_container" -eq 0 ]; then
        finding "OK" "containers.not_detected" "No container indicators found" ""
        return 0
    fi

    finding "MEDIUM" "containers.detected" "Running inside a container" ""

    # Mounted docker.sock inside the container is a well-known full escape.
    # Deliberately NOT using escal8_effective_access here: unlike host
    # sensitive files (where root is the expected, legitimate owner and a
    # plain -w test is a false positive), container processes very
    # commonly run AS root by design, and root-in-container having write
    # access to the host's docker.sock is itself the exploitable condition
    # - not a bypass of some other, more restrictive intended permission.
    # A plain -w test correctly models "can the process that's actually
    # running right now use this escape", which is what matters here.
    if [ -S /var/run/docker.sock ]; then
        if [ -w /var/run/docker.sock ]; then
            finding "CRITICAL" "containers.docker_sock" "docker.sock is mounted and writable inside the container" \
                "Access to the Docker socket typically allows spawning a privileged container to escape to the host."
        else
            finding "HIGH" "containers.docker_sock_ro" "docker.sock is mounted but not writable" ""
        fi
    fi

    # Overly permissive capabilities granted to the container itself.
    if have_readable /proc/self/status; then
        local capeff
        capeff="$(grep -m1 '^CapEff:' /proc/self/status 2>/dev/null | awk '{print $2}')"
        [ -n "$capeff" ] && finding "INFO" "containers.capeff" "Effective capability mask: $capeff" \
            "Decode with 'capsh --decode=$capeff' if capsh is available."
    fi

    # Privileged-container hint: full device access.
    if have_readable /dev && command_exists find; then
        local devcount
        devcount="$(find /dev -maxdepth 1 -type b 2>/dev/null | wc -l | tr -d ' ')"
        if [ -n "$devcount" ] && [ "$devcount" -gt 5 ] 2>/dev/null; then
            finding "MEDIUM" "containers.many_devices" "Unusually broad device access inside container ($devcount block devices in /dev)" \
                "May indicate a privileged container with host device access."
        fi
    fi
    return 0
}
