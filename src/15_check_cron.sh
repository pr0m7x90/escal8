# ------------------------------------------------------------------------------
# Check: cron / scheduled tasks
# ------------------------------------------------------------------------------

run_check_cron() {
    section "Scheduled Tasks (cron)"

    local found_any=0

    if have_readable /etc/crontab; then
        found_any=1
        finding "INFO" "cron.etc_crontab" "/etc/crontab contents" "$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' /etc/crontab 2>/dev/null)"
    fi

    for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
        if [ -d "$d" ]; then
            found_any=1
            local listing; listing="$(ls -la "$d" 2>/dev/null)"
            [ -n "$listing" ] && finding "INFO" "cron.dir.$(basename "$d")" "Contents of $d" "$listing"

            # Check directory and file writability using the current user's
            # effective access. The old -perm -0002-only scan missed group-
            # writable cron entries that the current user can actually modify.
            if command_exists find; then
                local dir_access dir_mode other_digit cron_file file_access file_mode
                escal8_effective_access "$d" w
                dir_access=$?
                if [ "$dir_access" -eq 0 ]; then
                    dir_mode="$(escal8_mode_digits "$d" 2>/dev/null)"
                    other_digit="${dir_mode:2:1}"
                    if [[ "$other_digit" =~ ^[0-7]$ ]] && (( (other_digit & 2) != 0 )); then
                        finding "CRITICAL" "cron.writable_dir.$(basename "$d")" "Cron directory is world-writable: $d" \
                            "Unprivileged users may be able to plant or replace scheduled jobs."
                    else
                        finding "HIGH" "cron.writable_dir.$(basename "$d")" "Cron directory is writable by the current user: $d" \
                            "Verify ownership, group membership, sticky-bit behavior, and which jobs are executed as root."
                    fi
                elif [ "$dir_access" -eq 2 ]; then
                    skip_check "cron.dir_access.$(basename "$d")" "$d writability" "could not determine effective write access"
                fi

                local cron_files="$ESCAL8_TMPDIR/cron_files_$(basename "$d").txt"
                find "$d" -maxdepth 1 -type f -print 2>/dev/null > "$cron_files"
                while IFS= read -r cron_file; do
                    [ -n "$cron_file" ] || continue
                    escal8_effective_access "$cron_file" w
                    file_access=$?
                    if [ "$file_access" -eq 0 ]; then
                        file_mode="$(escal8_mode_digits "$cron_file" 2>/dev/null)"
                        other_digit="${file_mode:2:1}"
                        if [[ "$other_digit" =~ ^[0-7]$ ]] && (( (other_digit & 2) != 0 )); then
                            finding "CRITICAL" "cron.writable_file.$(basename "$cron_file")" "Cron file is world-writable: $cron_file" \
                                "A world-writable scheduled job or cron definition can permit privilege escalation."
                        else
                            finding "HIGH" "cron.writable_file.$(basename "$cron_file")" "Cron file is writable by the current user: $cron_file" \
                                "Verify that this file is executed or parsed by a privileged scheduler."
                        fi
                    elif [ "$file_access" -eq 2 ]; then
                        skip_check "cron.file_access.$(basename "$cron_file")" "$cron_file writability" "could not determine effective write access"
                    fi
                done < "$cron_files"
            else
                skip_check "cron.writable" "$d cron permission review" "find not available"
            fi
        fi
    done

    if [ -d /var/spool/cron ] || [ -d /var/spool/cron/crontabs ]; then
        found_any=1
        local spool_dir="/var/spool/cron/crontabs"
        [ -d "$spool_dir" ] || spool_dir="/var/spool/cron"
        local listing; listing="$(ls -la "$spool_dir" 2>/dev/null)"
        [ -n "$listing" ] && finding "INFO" "cron.spool" "User crontab spool ($spool_dir)" "$listing"
    fi

    # Current user's own crontab, if crontab(1) exists.
    if command_exists crontab; then
        local mine; mine="$(crontab -l 2>/dev/null)"
        [ -n "$mine" ] && finding "INFO" "cron.mine" "Current user's crontab" "$mine"
    fi

    if [ "$found_any" -eq 0 ]; then
        skip_check "cron.all" "Cron enumeration" "no cron directories/files found or accessible"
    fi
    return 0
}
