# ------------------------------------------------------------------------------
# Check: SSH keys and daemon configuration
# ------------------------------------------------------------------------------

run_check_ssh() {
    section "SSH"

    local home_dir="${HOME:-}"
    if [ -z "$home_dir" ] && command_exists getent && command_exists awk; then
        home_dir="$(getent passwd "$(id -un 2>/dev/null)" 2>/dev/null | awk -F: '{print $6}')"
    fi

    if [ -n "$home_dir" ] && [ -d "$home_dir/.ssh" ]; then
        local listing; listing="$(ls -la "$home_dir/.ssh" 2>/dev/null)"
        [ -n "$listing" ] && finding "INFO" "ssh.user_dir" "$home_dir/.ssh contents" "$listing"

        for keyfile in "$home_dir"/.ssh/id_rsa "$home_dir"/.ssh/id_ed25519 "$home_dir"/.ssh/id_ecdsa "$home_dir"/.ssh/id_dsa; do
            [ -e "$keyfile" ] || continue
            escal8_effective_access "$keyfile" r
            case $? in
                0)
                    finding "HIGH" "ssh.private_key_readable" "Private SSH key is readable by an unprivileged user: $keyfile" \
                        "Could allow lateral movement if the key is used elsewhere with broader access. File contents are not included."
                    ;;
                2)
                    skip_check "ssh.private_key_access" "$keyfile readability" "could not determine effective access permissions"
                    ;;
            esac
        done

        if have_readable "$home_dir/.ssh/authorized_keys"; then
            finding "INFO" "ssh.authorized_keys" "authorized_keys present" "$(cat "$home_dir/.ssh/authorized_keys" 2>/dev/null)"
        fi
    else
        skip_check "ssh.user_dir" "User SSH directory enumeration" "no readable ~/.ssh directory found"
    fi

    if have_readable /etc/ssh/sshd_config; then
        local cfg
        cfg="$(grep -viE '^[[:space:]]*#|^[[:space:]]*$' /etc/ssh/sshd_config 2>/dev/null)"
        [ -n "$cfg" ] && finding "INFO" "ssh.sshd_config" "sshd_config (active directives)" "$cfg"

        if printf '%s' "$cfg" | grep -qiE '^[[:space:]]*PermitRootLogin[[:space:]]+yes'; then
            finding "MEDIUM" "ssh.permit_root_login" "sshd allows direct root login (PermitRootLogin yes)" ""
        fi
    else
        skip_check "ssh.sshd_config" "sshd configuration review" "/etc/ssh/sshd_config not readable"
    fi
    return 0
}
