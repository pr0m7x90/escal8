# ------------------------------------------------------------------------------
# Check: shell history and environment variables
# ------------------------------------------------------------------------------

_ESCAL8_SECRET_PATTERNS='(PASS|PASSWORD|SECRET|TOKEN|API_KEY|APIKEY|AWS_ACCESS|PRIVATE_KEY)'

run_check_historyenv() {
    section "History & Environment"

    local home_dir="${HOME:-}"
    for hf in "$home_dir/.bash_history" "$home_dir/.zsh_history" "$home_dir/.sh_history"; do
        if have_readable "$hf"; then
            local hits
            hits="$(grep -iE 'passw|secret|token|ssh |scp |sudo ' "$hf" 2>/dev/null | tail -n 20)"
            if [ -n "$hits" ]; then
                finding "MEDIUM" "historyenv.history_hits" "Potentially sensitive lines in $(basename "$hf")" "$hits"
            else
                finding "OK" "historyenv.history_clean" "$(basename "$hf") present, no obvious sensitive keywords in a quick scan" ""
            fi
        fi
    done

    # Scan current environment for variable names that often carry secrets.
    # We only ever inspect names/values already exposed to this process -
    # no escalation or cross-process access is attempted.
    local hits
    hits="$(env 2>/dev/null | grep -Ei "$_ESCAL8_SECRET_PATTERNS" | sed 's/=.*$/=<redacted>/')"
    if [ -n "$hits" ]; then
        finding "MEDIUM" "historyenv.env_secrets" "Environment variables with secret-like names" "$hits"
    else
        finding "OK" "historyenv.env_clean" "No obviously secret-named environment variables" ""
    fi
    return 0
}
