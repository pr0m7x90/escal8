# ------------------------------------------------------------------------------
# Check: users and groups
# ------------------------------------------------------------------------------

run_check_users() {
    section "Users & Groups"

    local who; who="$(run_safe id)"
    [ -n "$who" ] && finding "INFO" "users.whoami" "Current identity: $who" ""

    # Interesting group membership that often grants indirect root paths.
    local groups_str; groups_str="$(run_safe id -nG)"
    if [ -n "$groups_str" ]; then
        for g in docker lxd adm disk video root wheel shadow; do
            case " $groups_str " in
                *" $g "*)
                    case "$g" in
                        docker|lxd|disk|shadow)
                            finding "HIGH" "users.group.$g" "User is a member of the '$g' group" \
                                "Membership in '$g' commonly allows privilege escalation to root."
                            ;;
                        adm|video)
                            finding "MEDIUM" "users.group.$g" "User is a member of the '$g' group" \
                                "May grant access to logs or device files useful for further enumeration."
                            ;;
                        *)
                            finding "INFO" "users.group.$g" "User is a member of the '$g' group" ""
                            ;;
                    esac
                    ;;
            esac
        done
    else
        skip_check "users.groups" "Group membership" "id -nG unavailable"
    fi

    # Accounts with UID 0 other than root are an instant red flag.
    if have_readable /etc/passwd; then
        local uid0
        uid0="$(awk -F: '$3 == 0 { print $1 }' /etc/passwd 2>/dev/null | grep -v '^root$')"
        if [ -n "$uid0" ]; then
            finding "CRITICAL" "users.uid0" "Non-root account(s) with UID 0" "$uid0"
        else
            finding "OK" "users.uid0" "Only 'root' has UID 0" ""
        fi

        # Accounts with a login shell that might be usable interactively.
        local shells
        shells="$(awk -F: '$7 !~ /(nologin|false)$/ { print $1 ":" $7 }' /etc/passwd 2>/dev/null)"
        [ -n "$shells" ] && finding "INFO" "users.shells" "Accounts with an interactive shell" "$shells"
    else
        skip_check "users.passwd" "/etc/passwd analysis" "file not readable"
    fi

    # World-readable/writable shadow file would be catastrophic. Running as
    # root always passes a plain -r/-w test (root bypasses DAC), so that is
    # not itself a misconfiguration - escal8_effective_access instead
    # checks whether a non-root, non-group user could read/write it when
    # we're root, and falls back to the original direct test otherwise.
    if [ -e /etc/shadow ]; then
        escal8_effective_access /etc/shadow r
        case $? in
            0)
                finding "CRITICAL" "users.shadow_readable" "/etc/shadow is readable by unprivileged users" \
                    "Password hashes may be extractable for offline cracking."
                ;;
            2)
                skip_check "users.shadow_readable" "/etc/shadow readability" \
                    "running as root and 'stat' is unavailable, so the actual permission bits could not be inspected"
                ;;
        esac

        escal8_effective_access /etc/shadow w
        case $? in
            0)
                finding "CRITICAL" "users.shadow_writable" "/etc/shadow is writable by unprivileged users" \
                    "Password hashes could be overwritten to take over any account, including root."
                ;;
            2)
                skip_check "users.shadow_writable" "/etc/shadow writability" \
                    "running as root and 'stat' is unavailable, so the actual permission bits could not be inspected"
                ;;
        esac
    fi
    return 0
}
