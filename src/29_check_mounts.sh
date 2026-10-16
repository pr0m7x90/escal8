# ------------------------------------------------------------------------------
# Mount options relevant to common privilege-escalation paths
# ------------------------------------------------------------------------------
run_check_mounts() {
    subsection "Mount options and temporary execution surfaces"
    local target fstype opts tool=0 assessed=0
    if command_exists findmnt; then
        tool=1
        while IFS=' ' read -r target fstype opts; do
            [ -n "$target" ] || continue
            assessed=$((assessed+1))
            case "$target" in
                /tmp|/var/tmp|/dev/shm|/run/shm)
                    if [[ ",$opts," == *,rw,* ]]; then
                        if [[ ",$opts," != *,noexec,* ]]; then
                            finding MEDIUM "mount.exec_writable_tmp.$(basename "$target")" "Temporary mount is writable and does not show noexec" "$target ($fstype; $opts). This increases the usefulness of a writable staging location but is not by itself a privilege escalation."
                        else
                            finding INFO "mount.noexec_tmp.$(basename "$target")" "Temporary mount is marked noexec" "$target ($fstype; $opts)"
                        fi
                    fi
                    ;;
            esac
            if [ "$target" = "/" ]; then
                [[ ",$opts," == *,rw,* ]] && finding INFO "mount.root_rw" "Root filesystem is mounted read-write" "$opts (normal on many live systems; interpret with other findings)."
            fi
        done < <(findmnt -rn -o TARGET,FSTYPE,OPTIONS 2>/dev/null | awk 'NF>=3 {print $1, $2, $3}')
    fi
    if [ "$tool" -eq 0 ]; then
        finding SKIP "mount.findmnt_missing" "findmnt is unavailable; structured mount-option review skipped" "A /proc/mounts fallback is intentionally not used here because escaping/field parsing differs across systems."
    else
        finding INFO "mount.review_scope" "Mount review inspected ${assessed} visible mount entries" "Checks focus on common temporary execution surfaces and the root mount, not every filesystem security policy."
    fi
    # Writable bind-mounted host paths / container context can alter interpretation.
    if [ -e /.dockerenv ] || grep -qaE '(docker|containerd|kubepods|lxc)' /proc/1/cgroup 2>/dev/null; then
        finding INFO "mount.container_context" "Container context detected; mount visibility may be namespace-limited" "Host mounts and host-side permissions may not be visible from this namespace."
    fi
}
