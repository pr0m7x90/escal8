# ------------------------------------------------------------------------------
# Check: NFS exports (no_root_squash)
# ------------------------------------------------------------------------------

run_check_nfs() {
    section "NFS Exports"

    if have_readable /etc/exports; then
        local exports; exports="$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' /etc/exports 2>/dev/null)"
        if [ -n "$exports" ]; then
            finding "INFO" "nfs.exports" "/etc/exports contents" "$exports"
            if printf '%s' "$exports" | grep -q 'no_root_squash'; then
                finding "CRITICAL" "nfs.no_root_squash" "An NFS export uses no_root_squash" \
                    "A client mounting this export as root can create a SUID binary and execute it as root on this host."
            fi
        else
            finding "OK" "nfs.none" "/etc/exports present but empty/commented out" ""
        fi
    else
        skip_check "nfs.exports" "NFS export configuration" "/etc/exports not present or not readable"
    fi

    # Currently mounted NFS shares (relevant even without local export config).
    if have_readable /proc/mounts; then
        local mounted; mounted="$(grep ' nfs' /proc/mounts 2>/dev/null)"
        [ -n "$mounted" ] && finding "INFO" "nfs.mounted" "Currently mounted NFS shares" "$mounted"
    fi
    return 0
}
