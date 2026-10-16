# ------------------------------------------------------------------------------
# Check: sudo configuration
# ------------------------------------------------------------------------------

# A short, well-known list of GTFOBins-style sudo-exploitable binaries.
# Kept intentionally small/representative - this is a heuristic hint, not an
# exhaustive exploit database, and Escal8 never tries to use these itself.
_ESCAL8_SUDO_RISKY_BINS="vim vi view nano pico emacs less more pager find xargs awk gawk mawk sed perl perl5 python python2 python3 python3.8 python3.9 python3.10 python3.11 python3.12 pypy ruby irb php node nodejs lua luajit tclsh wish gdb strace ltrace env tee cp mv install chmod chown chgrp rsync tar zip unzip 7z busybox bash sh dash zsh ksh fish ash expect socat nc ncat netcat nmap tcpdump mysql psql sqlite3 ftp sftp ssh scp git docker podman kubectl runc systemctl journalctl mount umount dd cpio rpm dpkg apt apt-get yum dnf apk snap screen tmux script chroot unshare nsenter setcap setfacl passwd usermod groupmod useradd groupadd aria2c curl wget openssl gnuplot hping3 ionice ip jq ldapsearch logsave mail nice nohup pip pip3 pkexec start-stop-daemon telnet time watch xdg-user-dir xdotool zipinfo taskset ed ex gtester run-parts flock fuser lsof man-db socat ncat nc.traditional"

run_check_sudo() {
    section "Sudo Configuration"

    if ! command_exists sudo; then
        skip_check "sudo.list" "sudo privileges" "sudo not installed"
        return 0
    fi

    # -n (non-interactive) ensures we never hang or prompt for a password;
    # if it fails we just report that we couldn't check non-interactively.
    local out rc
    out="$(sudo -n -l 2>&1)"
    rc=$?

    if [ $rc -ne 0 ]; then
        finding "INFO" "sudo.list" "Could not list sudo privileges non-interactively" \
            "Either a password is required or the user has no sudo access."
        return 0
    fi

    finding "INFO" "sudo.list" "sudo -l output" "$out"

    if printf '%s' "$out" | grep -q 'NOPASSWD'; then
        finding "INFO" "sudo.nopasswd" "User has one or more NOPASSWD sudo entries" \
            "Passwordless sudo is not automatically privilege escalation; review each permitted command, arguments, run-as identity, and environment restrictions."
    fi

    if printf '%s' "$out" | grep -qE '\(ALL([[:space:]]*:[[:space:]]*ALL)?\)[[:space:]]*ALL'; then
        finding "CRITICAL" "sudo.all" "User can sudo as ALL users running ALL commands" \
            "Effectively equivalent to a direct root shell via 'sudo su' or similar."
    fi

    # Parse actual command entries and only assign HIGH to entries that can
    # run as root or ALL. A rule such as (daemon) /usr/bin/vim may be unusual,
    # but is not by itself a root-privilege escalation path. Do not treat a
    # binary name in a comment/header as an allowed command. Sudoers aliases,
    # command arguments, tags, plugins, and Defaults can still affect meaning;
    # this remains a review heuristic, not an exploitability proof.
    local sudo_line runas_spec command_spec command_name bin runas_root
    local sudo_entry_re='^[[:space:]]*\(([^)]*)\)[[:space:]]*(.*)$'
    local root_runas_re='(^|,)[[:space:]]*(root|ALL)[[:space:]]*(,|:|$)'
    while IFS= read -r sudo_line; do
        [[ "$sudo_line" =~ $sudo_entry_re ]] || continue
        runas_spec="${BASH_REMATCH[1]}"
        command_spec="${BASH_REMATCH[2]}"
        # Remove common sudo tags only at the beginning of the command list.
        while [[ "$command_spec" =~ ^(NOPASSWD|PASSWD|SETENV|NOSETENV|LOG_INPUT|NOLOG_INPUT|LOG_OUTPUT|NOLOG_OUTPUT):[[:space:]]*(.*)$ ]]; do
            command_spec="${BASH_REMATCH[2]}"
        done
        command_spec="${command_spec%%,*}"
        command_spec="${command_spec# }"
        command_spec="${command_spec%%[[:space:]]*}"
        [ -n "$command_spec" ] || continue
        runas_root=0
        # sudoers permits comma-separated run-as user lists. ALL may include
        # root; a named non-root identity must not be treated as root access.
        if [[ ",$runas_spec," =~ $root_runas_re ]]; then
            runas_root=1
        fi
        [ "$runas_root" -eq 1 ] || continue
        command_name="${command_spec##*/}"
        for bin in $_ESCAL8_SUDO_RISKY_BINS; do
            if [ "$command_name" = "$bin" ]; then
                finding "HIGH" "sudo.gtfobin.$bin" "Root/ALL sudo command entry matches commonly abusable program '$bin'" \
                    "Heuristic only. Verify the exact allowed arguments, run-as identity, environment restrictions, aliases, and binary behavior before concluding privilege escalation is possible."
                break
            fi
        done
    done <<EOF_SUDO_RISKY_LINES
$out
EOF_SUDO_RISKY_LINES

    # A command explicitly allowed as root/ALL and writable by this user is a
    # much stronger signal than NOPASSWD alone. Inspect only literal absolute
    # executable paths from sudo -l output; do not execute any listed command.
    if ! escal8_is_root; then
        local sudo_line sudo_cmd
        while IFS= read -r sudo_line; do
            printf '%s\n' "$sudo_line" | grep -Eq '^[[:space:]]*\((root|ALL)([[:space:]:)]|$)' || continue
            sudo_cmd="$(printf '%s\n' "$sudo_line" | sed -nE 's/^[[:space:]]*\([^)]*\)[[:space:]]*(NOPASSWD:[[:space:]]*)?(PASSWD:[[:space:]]*)?(SETENV:[[:space:]]*)?(NOSETENV:[[:space:]]*)?([^[:space:]]+).*/\5/p')"
            case "$sudo_cmd" in
                /*)
                    if [ -f "$sudo_cmd" ] && [ -w "$sudo_cmd" ]; then
                        finding "HIGH" "sudo.writable_command" "Sudo-allowed command is writable by the current user: $sudo_cmd" \
                            "A root-authorized command path writable by this user can permit code modification. Verify sudoers arguments and the exact file before concluding exploitability."
                    fi
                    ;;
            esac
        done <<EOF_SUDO_LINES
$out
EOF_SUDO_LINES
    fi

    # sudo version can itself be vulnerable (e.g. CVE-2021-3156 'Baron Samedit').
    local sver; sver="$(run_safe sudo -V | head -n1)"
    [ -n "$sver" ] && finding "INFO" "sudo.version" "sudo version: $sver" \
        "Cross-reference this version against known sudo CVEs."
    return 0
}
