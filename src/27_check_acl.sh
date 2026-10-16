# ------------------------------------------------------------------------------
# POSIX ACL review for privilege-sensitive paths (read-only)
# ------------------------------------------------------------------------------

# Return success only when a numeric ACL entry applies to the invoking UID or
# one of its supplementary groups AND its effective permissions include write.
# getfacl -e prints effective permissions when the ACL mask removes rights;
# getfacl -n avoids locale/name-resolution ambiguity. This prevents usernames
# containing "w" and masked-out write bits from producing false positives.
_escal8_acl_has_effective_write() {
    local acl_text="$1" uid="$2" groups="$3" owner_gid="$4"
    local line kind ident perms effective
    while IFS= read -r line; do
        [[ "$line" == user:*:* || "$line" == group:*:* ]] || continue
        kind="${line%%:*}"; line="${line#*:}"
        ident="${line%%:*}"; line="${line#*:}"
        perms="${line%%[[:space:]]*}"
        effective="$perms"
        if [[ "$line" == *'#effective:'* ]]; then
            effective="${line#*#effective:}"
            effective="${effective%%[[:space:]]*}"
        fi
        [[ "$effective" == *w* ]] || continue
        if [[ "$kind" == user && -n "$ident" && "$ident" == "$uid" ]]; then
            return 0
        fi
        if [[ "$kind" == group ]]; then
            if [[ -z "$ident" ]]; then
                [[ " $groups " == *" $owner_gid "* ]] && return 0
            elif [[ " $groups " == *" $ident "* ]]; then
                return 0
            fi
        fi
    done <<< "$acl_text"
    return 1
}

run_check_acl() {
    subsection "POSIX ACLs on privilege-sensitive paths"
    if ! command_exists getfacl; then
        finding SKIP "acl.getfacl_missing" "getfacl is unavailable; ACL-specific checks skipped" "Install the acl package on the audit workstation/target to enable this check."
        return 0
    fi
    local uid groups path owner acl owner_gid
    uid="$(id -u 2>/dev/null)"; groups=" $(id -G 2>/dev/null) "
    for path in /etc/passwd /etc/shadow /etc/sudoers /etc/crontab /etc/ld.so.preload /etc/ld.so.conf /etc/profile /etc/bash.bashrc /etc/ssh/sshd_config /usr/local/bin /usr/local/sbin /etc/cron.d /etc/systemd/system; do
        [ -e "$path" ] || continue
        owner="$(stat -Lc '%u' "$path" 2>/dev/null || stat -c '%u' "$path" 2>/dev/null)"
        [ "$owner" = "0" ] || continue
        owner_gid="$(stat -Lc '%g' "$path" 2>/dev/null || stat -c '%g' "$path" 2>/dev/null)"
        acl="$(getfacl -cpne -- "$path" 2>/dev/null)" || continue
        if _escal8_acl_has_effective_write "$acl" "$uid" "$groups" "$owner_gid"; then
            finding HIGH "acl.current_user_write.$(basename "$path")" "Effective ACL may grant the current user write access to a root-owned sensitive path" "$path (root-owned); effective ACL write entry detected. Review the full ACL and path semantics before concluding exploitability."
        fi
    done
    finding INFO "acl.review_scope" "ACL review completed for selected privilege-sensitive paths" "Only selected paths were inspected. This is not a filesystem-wide ACL inventory. ACL mask/effective rights and numeric IDs are considered."
}
