# ------------------------------------------------------------------------------
# Check: writable sensitive files and directories
# ------------------------------------------------------------------------------

_ESCAL8_SENSITIVE_FILES="/etc/passwd /etc/shadow /etc/sudoers /etc/crontab /etc/hosts /etc/ld.so.preload /etc/ld.so.conf"

run_check_writable() {
    section "Writable Sensitive Paths"

    # Root always passes a plain -w test (DAC bypass), which is expected -
    # root legitimately owns and can write these files. That's not a
    # misconfiguration, so use escal8_effective_access to ask the question
    # that actually matters: could a non-root, non-owning user write here?
    for f in $_ESCAL8_SENSITIVE_FILES; do
        [ -e "$f" ] || continue
        escal8_effective_access "$f" w
        case $? in
            0)
                finding "CRITICAL" "writable.file.$(basename "$f")" "$f is writable by unprivileged users" \
                    "Direct write access to this file can typically be leveraged to gain root."
                ;;
            2)
                skip_check "writable.file.$(basename "$f")" "$f writability" \
                    "running as root and 'stat' is unavailable, so the actual permission bits could not be inspected"
                ;;
        esac
    done

    # Writable systemd unit directories let an attacker plant a unit that
    # root (or systemd running as root) will later execute. Same root-vs-
    # unprivileged distinction as above.
    for d in /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system; do
        [ -d "$d" ] || continue
        escal8_effective_access "$d" w
        case $? in
            0)
                finding "HIGH" "writable.systemd_dir" "Writable (by unprivileged users) systemd unit directory: $d" \
                    "A malicious unit file placed here could run as root when triggered or on next boot."
                ;;
            2)
                skip_check "writable.systemd_dir" "$d writability" \
                    "running as root and 'stat' is unavailable, so the actual permission bits could not be inspected"
                ;;
        esac
    done

    # Find root-owned executables that the current non-root user can modify.
    # This complements the process-script check: a writable root-owned binary
    # is a potential escalation vector only if a privileged workflow executes it.
    # Do not run this check as root, because root's ordinary DAC bypass would
    # make every root-owned file appear writable.
    if ! command_exists find; then
        skip_check "writable.root_execs" "Root-owned writable executable scan" "find not available"
    elif escal8_is_root; then
        skip_check "writable.root_execs" "Root-owned writable executable scan" \
            "running as root; current-user writability is meaningful for non-root scans"
    else
        local root_exec_candidates="$ESCAL8_TMPDIR/root_writable_exec_candidates.txt"
        local root_exec_errors="$ESCAL8_TMPDIR/root_writable_exec_errors.txt"
        local scan_rc error_lines
        : > "$root_exec_candidates"
        : > "$root_exec_errors"

        if find / -xdev -type f -user root -perm -0100 \
            \( -perm -0020 -o -perm -0002 \) \
            ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" \
            -print > "$root_exec_candidates" 2> "$root_exec_errors"; then
            scan_rc=0
        else
            scan_rc=$?
        fi

        if [ "$scan_rc" -ne 0 ]; then
            error_lines="$(wc -l < "$root_exec_errors" 2>/dev/null)"
            error_lines="${error_lines//[[:space:]]/}"
            error_lines="${error_lines:-0}"
            if [ -s "$root_exec_candidates" ]; then
                finding "INFO" "writable.root_execs.partial" \
                    "Root-owned executable scan was partial" \
                    "find exited with status $scan_rc after discovering candidates; $error_lines diagnostic line(s) were recorded. Discovered candidates are still evaluated, but inaccessible paths may contain additional findings."
            else
                skip_check "writable.root_execs" "Root-owned writable executable scan" \
                    "find exited with status $scan_rc and discovered no candidates; $error_lines diagnostic line(s) were recorded"
            fi
        fi

        while IFS= read -r candidate; do
            [ -n "$candidate" ] || continue
            if [ -w "$candidate" ]; then
                finding "HIGH" "writable.root_exec" \
                    "Root-owned executable is writable by the current user: $candidate" \
                    "Potential escalation if a privileged service, scheduled task, or administrator executes it. Verify its actual execution path before treating it as exploitable."
            fi
        done < "$root_exec_candidates"
    fi

    # Writable directories on PATH are covered separately in check_path, but
    # we also scan for a handful of common writable-by-group-or-world temp
    # and service directories that scripts/services often trust blindly.
    if command_exists find; then
        local dirs="/opt /srv /var/www /var/backups"
        for d in $dirs; do
            [ -d "$d" ] || continue
            local w
            w="$(find "$d" -maxdepth 2 -perm -0002 -type d 2>/dev/null)"
            [ -n "$w" ] && finding "MEDIUM" "writable.dir.$(basename "$d")" "World-writable subdirectories under $d" "$w"
        done
    else
        skip_check "writable.dirs" "World-writable directory scan" "find not available"
    fi
    return 0
}
