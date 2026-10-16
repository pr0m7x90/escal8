# ------------------------------------------------------------------------------
# Sudo timestamp / environment metadata (never dump token contents)
# ------------------------------------------------------------------------------
run_check_sudotokens() {
    subsection "Sudo timestamp and session metadata"
    local uid user dir f count=0
    uid="$(id -u 2>/dev/null)"; user="$(id -un 2>/dev/null)"
    # Environment variable NAMES only; values may contain secrets and are never printed.
    local envnames=""
    if [ -r "/proc/$$/environ" ]; then
        envnames="$(tr '\0' '\n' < "/proc/$$/environ" 2>/dev/null | cut -d= -f1 | grep -E '^(SUDO_|SSH_AUTH_SOCK$|SSH_AGENT_PID$)' | sort -u | tr '\n' ' ')"
    fi
    if [ -n "$envnames" ]; then
        finding INFO "sudo_tokens.environment_metadata" "Sudo/SSH session-related environment variable names are present" "$envnames (values intentionally redacted; presence alone is not a vulnerability)."
    else
        finding OK "sudo_tokens.no_env_metadata" "No common sudo/SSH agent environment names found in this process environment" "This does not prove that no cached sudo timestamp or agent socket exists."
    fi
    for dir in "/run/sudo/ts" "/var/run/sudo/ts"; do
        [ -d "$dir" ] || continue
        for f in "$dir"/*; do
            [ -e "$f" ] || continue
            count=$((count+1))
            # Report metadata only, never read timestamp file contents.
            finding INFO "sudo_tokens.timestamp_metadata" "Sudo timestamp metadata file exists" "$f; $(stat -c 'owner=%U mode=%a size=%s' "$f" 2>/dev/null || stat -f 'owner=%Su mode=%Lp size=%z' "$f" 2>/dev/null || echo 'metadata unavailable'). Existence is normal and is not proof of a reusable credential."
        done
    done
    [ "$count" -gt 0 ] || finding OK "sudo_tokens.no_timestamp_files" "No visible sudo timestamp files found in common locations" "Other sudo implementations or namespaces may store state elsewhere."
}
