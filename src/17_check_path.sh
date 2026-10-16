# ------------------------------------------------------------------------------
# Check: PATH hijacking opportunities
# ------------------------------------------------------------------------------

run_check_path() {
    section "PATH Integrity"

    finding "INFO" "path.value" "Current PATH" "$PATH"

    local old_ifs="$IFS"
    IFS=':'
    local dir
    for dir in $PATH; do
        IFS="$old_ifs"
        [ -z "$dir" ] && {
            finding "HIGH" "path.empty_entry" "PATH contains an empty entry (resolves to current directory)" ""
            continue
        }
        if [ "$dir" = "." ]; then
            finding "HIGH" "path.dot" "PATH contains '.' (current working directory)" \
                "Running common commands from an attacker-writable directory could execute planted binaries."
            continue
        fi
        if [ -d "$dir" ]; then
            # PATH risk is about whether OTHER users can plant an executable,
            # not whether the account running Escal8 can write to its own
            # directory. In particular, [ -w ] is true for a user's own
            # ~/.local/bin even when it is mode 755. Check group/other write
            # bits instead, dereferencing symlinks via escal8_mode_digits.
            local mode_digits group_digit other_digit
            mode_digits="$(escal8_mode_digits "$dir")"
            if [ -z "$mode_digits" ]; then
                skip_check "path.writable" "'$dir' writability" \
                    "stat is unavailable or permissions could not be inspected"
                IFS=':'
                continue
            fi
            group_digit="${mode_digits:1:1}"
            other_digit="${mode_digits:2:1}"
            if [[ "$group_digit" =~ ^[0-7]$ && "$other_digit" =~ ^[0-7]$ ]] && \
               (( (group_digit & 2) != 0 || (other_digit & 2) != 0 )); then
                finding "CRITICAL" "path.writable" "PATH directory '$dir' is writable by unprivileged users" \
                    "The directory grants write permission to its owning group or to other users. Verify group membership and any privileged process that uses this PATH."
            fi
        fi
        IFS=':'
    done
    IFS="$old_ifs"
    return 0
}
