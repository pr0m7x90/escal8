# ------------------------------------------------------------------------------
# Check: DevOps and orchestration control surfaces (metadata only)
# ------------------------------------------------------------------------------

run_check_devops() {
    section "DevOps and Orchestration Surfaces"

    local path owner mode desc count=0 output=''
    local candidates='/var/run/docker.sock /run/containerd/containerd.sock /run/podman/podman.sock /var/run/podman/podman.sock /etc/kubernetes/admin.conf /etc/kubernetes/kubelet.conf /var/lib/kubelet/config.yaml /etc/rancher/k3s/k3s.yaml /etc/rancher/rke2/rke2.yaml /var/lib/rancher/k3s/server/node-token /etc/containers/registries.conf /etc/gitlab-runner/config.toml /etc/jenkins/jenkins.model.JenkinsLocationConfiguration.xml'

    for path in $candidates; do
        [ -e "$path" ] || [ -S "$path" ] || continue
        count=$((count + 1))
        owner="$(stat -Lc '%U' "$path" 2>/dev/null || stat -f '%Su' "$path" 2>/dev/null)"
        mode="$(stat -Lc '%a' "$path" 2>/dev/null || stat -f '%Lp' "$path" 2>/dev/null)"
        [ -n "$owner" ] || owner='unknown'
        [ -n "$mode" ] || mode='unknown'
        output="${output}${path} (owner=${owner}, mode=${mode})"$'\n'
        if [ -S "$path" ] && [ -w "$path" ]; then
            finding "HIGH" "devops.writable_control_socket" "Current user can write to a container/runtime control socket: $path" \
                "A writable control socket may confer broad host or workload control. Confirm the socket's daemon, namespace, and authorization policy; Escal8 did not send commands to it."
        elif [ -f "$path" ]; then
            case "$mode" in
                *[0-7])
                    last_digit="${mode: -1}"
                    if [ $((10#$last_digit & 4)) -ne 0 ]; then
                        finding "HIGH" "devops.world_readable_control_config" "Orchestration/control configuration is world-readable: $path" \
                            "Metadata only. Confirm whether this file contains credentials or privileged cluster configuration; contents were not read."
                    fi
                    ;;
            esac
        fi
    done

    if [ "$count" -gt 0 ]; then
        finding "INFO" "devops.control_surfaces" "DevOps/orchestration control-surface paths found ($count)" "$output"
    else
        finding "OK" "devops.no_control_surfaces" "No common DevOps/orchestration control-surface paths found" \
            "This bounded list is not a complete inventory of runtimes, clusters, CI agents, or custom installations."
    fi

    # Report membership names only; group membership can be useful context but
    # does not by itself prove that a daemon socket is accessible.
    if command_exists id; then
        local groups
        groups="$(id -nG 2>/dev/null)"
        if printf ' %s ' "$groups" | grep -Eq ' (docker|lxd|libvirt|kvm|incus|podman) '; then
            finding "MEDIUM" "devops.runtime_groups" "User belongs to a group associated with container/VM management" \
                "Groups: $groups. Effective control depends on host policy, device/socket permissions, daemon configuration, and namespace boundaries."
        fi
    fi
    return 0
}
