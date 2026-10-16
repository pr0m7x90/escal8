# ------------------------------------------------------------------------------
# Check: potentially sensitive files readable by the current user
# ------------------------------------------------------------------------------

run_check_credentials() {
    section "Potential Credential Files"

    if ! command_exists find; then
        skip_check "credentials.find" "Potential credential-file discovery" "find not available"
        return 0
    fi

    local scan_roots="/home /opt /srv /var/www /etc"
    local tmp="$ESCAL8_TMPDIR/credential_candidates.txt"
    : > "$tmp" 2>/dev/null || {
        skip_check "credentials.temp" "Potential credential-file discovery" "could not create candidate list"
        return 0
    }

    local rootdir
    for rootdir in $scan_roots; do
        [ -d "$rootdir" ] || continue
        find "$rootdir" -maxdepth 6 -type f \
            \( -name '.env' -o -name '.netrc' -o -name '.git-credentials' \
               -o -name 'credentials' -o -name 'credentials.json' \
               -o -name 'id_rsa' -o -name 'id_ed25519' -o -name 'id_ecdsa' \
               -o -name '*.kdbx' -o -name '*password*' -o -name '*secret*' \
               -o -name '*.pem' -o -name '*.p12' -o -name '*.pfx' \
               -o -name 'config.php' -o -name 'wp-config.php' \) \
            -print 2>/dev/null >> "$tmp"
    done

    local path count=0 shown=0 unknown=0 access candidates=''
    while IFS= read -r path; do
        [ -n "$path" ] || continue
        count=$((count + 1))
        # When running as root, do not confuse root's DAC bypass with a
        # credential file readable by an unprivileged account.
        escal8_effective_access "$path" r
        access=$?
        if [ "$access" -eq 2 ]; then
            unknown=$((unknown + 1))
            continue
        elif [ "$access" -ne 0 ]; then
            continue
        fi
        # Only report paths and metadata; never include secret file contents.
        if [ "$shown" -lt 200 ]; then
            candidates="${candidates}${path}"$'\n'
            shown=$((shown + 1))
        fi
    done < "$tmp"

    if [ "$shown" -gt 0 ]; then
        finding "MEDIUM" "credentials.readable_candidates" \
            "Potential credential/configuration files readable by the current user ($shown shown)" \
            "$candidates"
        if [ "$count" -gt 200 ]; then
            finding "INFO" "credentials.limit" "Credential candidate list truncated" \
                "More than 200 candidate paths were found; only the first 200 readable paths are shown."
        fi
    else
        finding "OK" "credentials.none" "No matching readable credential-file candidates found in scanned locations" \
            "Scanned existing directories among: $scan_roots (maximum depth 6). This is not a complete filesystem secret scan."
    fi
    if [ "$unknown" -gt 0 ]; then
        finding "INFO" "credentials.access_unknown" "Could not assess access to $unknown credential-file candidate(s)" \
            "Permission mode inspection was unavailable for some candidates; they were not treated as readable."
    fi
    return 0
}
