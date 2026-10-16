# ------------------------------------------------------------------------------
# Check: deleted files still held open by processes
# ------------------------------------------------------------------------------
run_check_deleted_files() {
    section "Deleted Files Held Open"
    local out='' rc=0
    # When a fixture proc root is supplied, exercise that fixture directly;
    # host lsof output must not short-circuit the deterministic test path.
    if [ -z "${ESCAL8_PROC_ROOT:-}" ] && command_exists lsof; then
        out="$(lsof -nP +L1 2>/dev/null | head -n 100)"
        rc=$?
        if [ -n "$out" ]; then
            finding INFO "deleted_files.open" "Processes hold deleted files open" "$out"
            finding INFO "deleted_files.interpretation" "Deleted-open-file entries need manual triage" "This may indicate deleted logs, replaced executables, or ordinary temporary files. Escal8 does not infer privilege escalation from this alone."
            return 0
        fi
        # lsof may return no rows because of permission limits; fall through to
        # /proc metadata as a second, independent source.
    fi

    # Linux /proc fallback: read symlink targets only; never read file contents.
    # ESCAL8_PROC_ROOT is overridable solely to make fixture-based tests possible.
    local proc_root="${ESCAL8_PROC_ROOT:-/proc}" fd pid comm target shown=0 matches='' total=0
    if [ -d "$proc_root" ] && command_exists readlink; then
        for fd in "$proc_root"/[0-9]*/fd/*; do
            [ -L "$fd" ] || continue
            target="$(readlink -- "$fd" 2>/dev/null)" || continue
            case "$target" in
                *' (deleted)')
                    total=$((total + 1))
                    [ "$shown" -lt 100 ] || continue
                    pid="${fd#"$proc_root"/}"; pid="${pid%%/*}"
                    comm="$(cat "$proc_root/$pid/comm" 2>/dev/null | head -n 1)"
                    [ -n "$comm" ] || comm='unknown'
                    matches="${matches}pid=${pid} comm=${comm} fd=${fd##*/} target=${target}"$'\n'
                    shown=$((shown + 1))
                    ;;
            esac
        done
        if [ "$total" -gt 0 ]; then
            finding INFO "deleted_files.open" "Processes hold deleted files open ($total visible; $shown shown)" "$matches"
            finding INFO "deleted_files.interpretation" "Deleted-open-file entries need manual triage" "Only visible /proc file-descriptor symlink metadata was inspected. Escal8 did not read file contents; process visibility depends on procfs mount options and privileges."
            [ "$total" -le 100 ] || finding INFO "deleted_files.truncated" "Deleted-open-file listing truncated" "Showing at most 100 visible file descriptors."
            return 0
        fi
        finding INFO "deleted_files.none_visible" "No deleted-open files were visible via lsof or /proc" "Absence is not proof of complete visibility; procfs restrictions, namespaces, and permissions may hide descriptors."
        return 0
    fi
    skip_check "deleted_files.unavailable" "Deleted-open-file enumeration" "lsof is unavailable and /proc file-descriptor metadata cannot be inspected"
    return 0
}
