# ------------------------------------------------------------------------------
# Check: network interfaces and listening sockets
# ------------------------------------------------------------------------------

run_check_network() {
    section "Network"

    if command_exists ip; then
        finding "INFO" "network.interfaces" "Network interfaces (ip addr)" "$(run_safe ip -o addr show)"
    elif command_exists ifconfig; then
        finding "INFO" "network.interfaces" "Network interfaces (ifconfig)" "$(run_safe ifconfig -a)"
    else
        skip_check "network.interfaces" "Network interface listing" "neither ip nor ifconfig available"
    fi

    # Prefer ss, fall back to netstat, fall back to raw /proc/net parsing so
    # the check still works on minimal containers with neither tool.
    if command_exists ss; then
        finding "INFO" "network.listening" "Listening sockets (ss)" "$(run_safe ss -tulpn)"
    elif command_exists netstat; then
        finding "INFO" "network.listening" "Listening sockets (netstat)" "$(run_safe netstat -tulpn)"
    elif have_readable /proc/net/tcp; then
        # Avoid awk's strtonum(), which is a gawk extension and is NOT
        # available under mawk or busybox awk. Extract the hex port field
        # with awk (portable) and convert hex->decimal using a bash
        # built-in arithmetic context instead, which works everywhere bash
        # itself runs.
        local hexports ports="" hp
        hexports="$(awk 'NR>1 { split($2,a,":"); print a[2] }' /proc/net/tcp 2>/dev/null)"
        if [ -n "$hexports" ]; then
            while IFS= read -r hp; do
                [ -z "$hp" ] && continue
                ports="$ports $((16#$hp))"
            done <<EOF
$hexports
EOF
            ports="$(printf '%s\n' $ports | sort -nu)"
        fi
        if [ -n "$ports" ]; then
            finding "INFO" "network.listening" "Local ports in use (parsed from /proc/net/tcp, IPv4 only)" "$ports"
        else
            skip_check "network.listening" "Listening socket enumeration" "could not parse /proc/net/tcp"
        fi
    else
        skip_check "network.listening" "Listening socket enumeration" "no ss, netstat, or /proc/net/tcp available"
    fi

    if have_readable /etc/hosts; then
        finding "INFO" "network.hosts" "/etc/hosts contents" "$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' /etc/hosts 2>/dev/null)"
    fi

    if have_readable /etc/resolv.conf; then
        finding "INFO" "network.resolv" "DNS configuration" "$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' /etc/resolv.conf 2>/dev/null)"
    fi
    return 0
}
