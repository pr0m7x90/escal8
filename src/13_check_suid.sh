# ------------------------------------------------------------------------------
# Check: SUID / SGID binaries
# ------------------------------------------------------------------------------

# Candidate list is deliberately a heuristic subset of GTFOBins, not a complete
# replacement for LinPEAS's generated GTFOBins-derived matching database.
_ESCAL8_SUID_KNOWN_RISKY="nmap vim vi view nano pico emacs find xargs awk gawk sed perl perl5 python python2 python3 python3.8 python3.9 python3.10 python3.11 python3.12 pypy ruby irb php node nodejs lua luajit gcc cc clang gdb strace ltrace env tee cp mv install chmod chown chgrp rsync tar zip unzip 7z busybox bash sh dash zsh ksh fish ash expect socat nc ncat netcat nmap tcpdump mysql psql sqlite3 ftp git docker podman kubectl runc systemctl journalctl mount umount dd cpio rpm dpkg apt apt-get yum dnf apk snap screen tmux script chroot unshare nsenter setcap setfacl passwd usermod groupmod useradd groupadd"

run_check_suid() {
    section "SUID / SGID Binaries"

    if ! command_exists find; then
        skip_check "suid.scan" "SUID/SGID filesystem scan" "find not available"
        return 0
    fi

    # Scan the root filesystem once and bound traversal time. Large /opt or
    # language-package trees can otherwise stall enumeration for minutes. A
    # timeout is reported as partial coverage, never as a clean result.
    # Additional persistent mounts are scanned only after the root scan
    # completes, and each distinct device is visited at most once.
    local suid_file="$ESCAL8_TMPDIR/suid_list.txt"
    local sgid_file="$ESCAL8_TMPDIR/sgid_list.txt"
    local all_file="$ESCAL8_TMPDIR/suid_sgid_all.txt"
    local raw_file="$ESCAL8_TMPDIR/suid_sgid_raw.txt"
    local scan_timeout="${ESCAL8_FIND_TIMEOUT:-20}"
    case "$scan_timeout" in ''|*[!0-9]*) scan_timeout=20 ;; esac
    [ "$scan_timeout" -gt 0 ] || scan_timeout=20
    : > "$suid_file"; : > "$sgid_file"; : > "$raw_file"
    local scan_rc=0
    if command_exists timeout; then
        timeout "${scan_timeout}s" find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune -o -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null > "$raw_file"
        scan_rc=$?
    else
        find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune -o -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null > "$raw_file"
        scan_rc=$?
    fi
    local bin
    while IFS= read -r bin; do
        [ -n "$bin" ] || continue
        [[ -u "$bin" ]] && printf '%s\n' "$bin" >> "$suid_file"
        [[ -g "$bin" ]] && printf '%s\n' "$bin" >> "$sgid_file"
    done < "$raw_file"
    if [ "$scan_rc" -eq 0 ] && command_exists findmnt && command_exists stat; then
        local root_dev mountpoint mount_dev
        root_dev="$(stat -Lc '%d' / 2>/dev/null)"
        declare -A _escal8_seen_mount_devices=()
        [ -n "$root_dev" ] && _escal8_seen_mount_devices["$root_dev"]=1
        while IFS= read -r mountpoint; do
            case "$mountpoint" in /|/proc|/proc/*|/sys|/sys/*|/dev|/dev/*|/run|/run/*) continue ;; esac
            [ -d "$mountpoint" ] || continue
            mount_dev="$(stat -Lc '%d' "$mountpoint" 2>/dev/null)"
            [ -n "$mount_dev" ] || continue
            [ -z "${_escal8_seen_mount_devices[$mount_dev]:-}" ] || continue
            _escal8_seen_mount_devices["$mount_dev"]=1
            if command_exists timeout; then
                timeout "${scan_timeout}s" find "$mountpoint" -xdev -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null > "$ESCAL8_TMPDIR/mount_suid_sgid.txt"
                local mount_rc=$?
                if [ "$mount_rc" -ne 0 ]; then
                    finding INFO "suid.mount_scan_partial" "SUID/SGID scan of mount was incomplete: $mountpoint" "A per-filesystem scan exceeded its time limit or failed; findings from this mount may be incomplete."
                    continue
                fi
            else
                find "$mountpoint" -xdev -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null > "$ESCAL8_TMPDIR/mount_suid_sgid.txt"
            fi
            while IFS= read -r bin; do
                [ -n "$bin" ] || continue
                [[ -u "$bin" ]] && printf '%s\n' "$bin" >> "$suid_file"
                [[ -g "$bin" ]] && printf '%s\n' "$bin" >> "$sgid_file"
            done < "$ESCAL8_TMPDIR/mount_suid_sgid.txt"
        done < <(findmnt -rn -t ext2,ext3,ext4,xfs,btrfs,zfs,nfs,nfs4,cifs,fuseblk,vfat,exfat,ntfs -o TARGET 2>/dev/null)
    fi
    sort -u "$suid_file" -o "$suid_file" 2>/dev/null
    sort -u "$sgid_file" -o "$sgid_file" 2>/dev/null
    cat "$suid_file" "$sgid_file" | sort -u > "$all_file"
    if [ "$scan_rc" -eq 124 ] || [ "$scan_rc" -eq 137 ]; then
        finding INFO "suid.scan_timeout" "SUID/SGID scan reached its ${scan_timeout}s time limit; results are partial" "Increase ESCAL8_FIND_TIMEOUT to allow a longer scan. Partial results must not be interpreted as a complete inventory."
    fi

    local suid_count sgid_count total_count
    suid_count="$(wc -l < "$suid_file" 2>/dev/null | tr -d ' ')"
    sgid_count="$(wc -l < "$sgid_file" 2>/dev/null | tr -d ' ')"
    total_count="$(wc -l < "$all_file" 2>/dev/null | tr -d ' ')"
    suid_count="${suid_count:-0}"; sgid_count="${sgid_count:-0}"; total_count="${total_count:-0}"

    # Non-zero find status may still yield usable paths if traversal hits
    # restricted directories. Preserve those results and disclose partial coverage.
    if [ "$scan_rc" -ne 0 ] && [ "$scan_rc" -ne 124 ] && [ "$scan_rc" -ne 137 ]; then
        if [ "$total_count" -gt 0 ]; then
            finding INFO "suid.scan_partial" "SUID/SGID scan was partial; results were collected" "find exit status: $scan_rc; found $suid_count SUID and $sgid_count SGID files. Access restrictions may hide additional files."
        else
            finding SKIP "suid.scan_error" "SUID/SGID scan returned an error and no results" "find exit status: $scan_rc; no usable inventory was collected."
        fi
    fi

    if [ "$total_count" -eq 0 ]; then
        finding "INFO" "suid.scan_empty" "No SUID/SGID results were returned" "This may mean no matching files were found or filesystem traversal was restricted; check scan permissions and mounted filesystems."
        return 0
    fi

    # Never dump an unbounded filesystem inventory into terminal or JSON/HTML
    # reports. Shared build/container environments can legitimately have huge
    # SGID trees; report totals plus a bounded sample and an explicit truncation
    # notice so output size remains predictable.
    local inventory_limit=100 suid_sample sgid_sample
    suid_sample="$(head -n "$inventory_limit" "$suid_file" 2>/dev/null)"
    sgid_sample="$(head -n "$inventory_limit" "$sgid_file" 2>/dev/null)"
    finding "INFO" "suid.count" "Found $suid_count SUID and $sgid_count SGID files" "SUID sample (up to $inventory_limit):
${suid_sample:-<none>}
SGID sample (up to $inventory_limit):
${sgid_sample:-<none>}"
    if [ "$suid_count" -gt "$inventory_limit" ] || [ "$sgid_count" -gt "$inventory_limit" ]; then
        finding "INFO" "suid.inventory_truncated" "SUID/SGID inventory sample truncated" \
            "The full inventory is intentionally not embedded in reports. Counts are complete only if the filesystem scan completed; the displayed path samples are limited to $inventory_limit entries per class."
    fi

    while IFS= read -r bin; do
        [ -n "$bin" ] || continue
        local base
        base="$(basename "$bin" 2>/dev/null)"
        for risky in $_ESCAL8_SUID_KNOWN_RISKY; do
            if [ "$base" = "$risky" ]; then
                finding "MEDIUM" "suid.risky.$base" "SUID binary matches a commonly abusable program: $bin" \
                    "Name-based matching alone does not establish an exploitable privilege-escalation path. Verify file ownership, version, effective SUID behavior, and the exact GTFOBins technique before assigning higher severity."
                break
            fi
        done
    done < "$suid_file"

    local unusual
    local unusual_count
    unusual_count="$(grep -vcE '^/(usr/bin|usr/sbin|bin|sbin|usr/lib|usr/libexec)/' "$all_file" 2>/dev/null)"
    unusual_count="${unusual_count:-0}"
    if [ "$unusual_count" -gt 0 ]; then
        unusual="$(grep -vE '^/(usr/bin|usr/sbin|bin|sbin|usr/lib|usr/libexec)/' "$all_file" 2>/dev/null | head -n 100)"
        finding "MEDIUM" "suid.unusual_location" "SUID/SGID files outside common system directories (review provenance; $unusual_count total)" "$unusual"
        if [ "$unusual_count" -gt 100 ]; then
            finding "INFO" "suid.unusual_location_truncated" "Unusual-location listing truncated" \
                "Showing the first 100 paths only. Review the complete inventory with a dedicated, controlled filesystem audit if required."
        fi
    fi
    return 0
}
