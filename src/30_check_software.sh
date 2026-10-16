# ------------------------------------------------------------------------------
# Package-manager and development-tool inventory for follow-up version review
# ------------------------------------------------------------------------------
run_check_software() {
    subsection "Installed software and potentially relevant tool inventory"
    local os="unknown" count=0 pkg
    if [ -r /etc/os-release ]; then
        os="$(grep -E '^(ID|VERSION_ID|VERSION_CODENAME)=' /etc/os-release 2>/dev/null | tr '\n' ' ')"
    fi
    finding INFO "software.os_release" "Platform identity for version-specific follow-up" "$os"
    if command_exists dpkg-query; then
        local pkgs
        pkgs="$(dpkg-query -W -f='${binary:Package}\t${Version}\n' 2>/dev/null | grep -Ei '^(sudo|openssh-server|polkit|policykit|pkexec|docker|containerd|runc|podman|linux-image|linux-headers|apache2|nginx|mysql-server|mariadb-server|postgresql|redis-server|screen|tmux|vim|nano|perl|python3|ruby|php|nodejs|gcc|make)([^[:alnum:]_-]|$)' | head -n 80)"
        if [ -n "$pkgs" ]; then
            while IFS= read -r pkg; do
                [ -n "$pkg" ] || continue; count=$((count+1))
                finding INFO "software.package_inventory.$count" "Installed package candidate for manual version/CVE verification" "$pkg"
            done <<< "$pkgs"
        fi
    elif command_exists rpm; then
        while IFS= read -r pkg; do
            [ -n "$pkg" ] || continue; count=$((count+1))
            finding INFO "software.package_inventory.$count" "Installed package candidate for manual version/CVE verification" "$pkg"
        done < <(rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\n' 2>/dev/null | grep -Ei '^(sudo|openssh|polkit|docker|containerd|runc|podman|kernel|httpd|nginx|mariadb|postgresql|redis|screen|tmux|vim|perl|python|ruby|php|nodejs|gcc|make)([^[:alnum:]_-]|$)' | head -n 80)
    elif command_exists apk; then
        while IFS= read -r pkg; do
            [ -n "$pkg" ] || continue; count=$((count+1))
            finding INFO "software.package_inventory.$count" "Installed package candidate for manual version/CVE verification" "$pkg"
        done < <(apk info -v 2>/dev/null | grep -Ei '^(sudo|openssh|polkit|docker|containerd|runc|podman|linux|apache2|nginx|mariadb|postgresql|redis|screen|tmux|vim|perl|python|ruby|php|nodejs|gcc|make)([^[:alnum:]_-]|$)' | head -n 80)
    else
        finding SKIP "software.package_manager_missing" "No supported package query tool detected" "Tried dpkg-query, rpm, and apk."
    fi
    finding INFO "software.version_matching_limit" "Package inventory is not a vulnerability verdict" "Escal8 does not currently ship a maintained vendor-aware CVE database and does not infer vulnerability from version strings alone. Validate package versions against the distribution's security tracker, including backported fixes."
}
