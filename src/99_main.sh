# ------------------------------------------------------------------------------
# Main orchestration
# ------------------------------------------------------------------------------

escal8_print_banner() {
    [ "$ESCAL8_QUIET" -eq 1 ] && return 0
    printf '%s%s v%s%s - Linux Privilege Escalation Enumeration\n' "$C_BOLD$C_CYAN" "$ESCAL8_NAME" "$ESCAL8_VERSION" "$C_RESET"
    printf '%sRead-only enumeration only. Use only on systems you are authorized to test.%s\n' "$C_DIM" "$C_RESET"
    printf 'Started: %s | Profile: %s\n' "$(human_time)" "$ESCAL8_PROFILE"
}

# Dispatch table: check keyword -> function name. A plain case statement is
# used instead of indirect variable expansion so this works unmodified under
# older bash (no need for namerefs here).
_escal8_run_one_check() {
    case "$1" in
        system)       run_check_system ;;
        users)        run_check_users ;;
        sudo)         run_check_sudo ;;
        suid)         run_check_suid ;;
        capabilities) run_check_capabilities ;;
        cron)         run_check_cron ;;
        writable)     run_check_writable ;;
        path)         run_check_path ;;
        network)      run_check_network ;;
        services)     run_check_services ;;
        processes)    run_check_processes ;;
        containers)   run_check_containers ;;
        nfs)          run_check_nfs ;;
        ssh)          run_check_ssh ;;
        historyenv)   run_check_historyenv ;;
        credentials)  run_check_credentials ;;
        acl)          run_check_acl ;;
        sudotokens)   run_check_sudotokens ;;
        mounts)       run_check_mounts ;;
        software)     run_check_software ;;
        kernel)       run_check_kernel ;;
        systemd_timers) run_check_systemd_timers ;;
        polkit)       run_check_polkit ;;
        kernel_hardening) run_check_kernel_hardening ;;
        deleted_files) run_check_deleted_files ;;
        cloud) run_check_cloud ;;
        devops) run_check_devops ;;
        system_surfaces) run_check_system_surfaces ;;
        *)
            # Should be unreachable from the CLI: escal8_parse_args now
            # validates every --checks entry against ESCAL8_ALL_CHECKS
            # before anything runs (see src/03_args.sh), rejecting unknown
            # names with exit code 2. This remains purely as a defensive
            # fallback against a maintainer letting ESCAL8_ALL_CHECKS and
            # this dispatch table drift out of sync.
            printf 'Warning: unknown check "%s" ignored\n' "$1" >&2
            return 1
            ;;
    esac
}

# escal8_init_check_coverage
# Every check Escal8 knows about starts out "unrequested"; the dispatch
# loop below promotes each one actually selected for this run to
# "completed", "skipped", or "failed" as it executes. This lets the
# summary and JSON/HTML reports clearly distinguish "we looked and it's
# clean", "we looked but could assess nothing at all" (every sub-check
# inside it hit a missing tool), "this wasn't part of the requested
# profile/--checks list", and "this crashed unexpectedly" (an Escal8 bug,
# not a target finding) - four different things that all look identical
# if you only see "no CRITICAL findings for X".
escal8_init_check_coverage() {
    local c
    for c in $ESCAL8_ALL_CHECKS; do
        ESCAL8_CHECK_STATUS[$c]="unrequested"
    done
}

escal8_main() {
    escal8_parse_args "$@"
    _escal8_colors_init
    escal8_init_runtime
    trap escal8_cleanup_runtime EXIT INT TERM
    escal8_init_check_coverage

    escal8_print_banner

    local chk rc
    for chk in $ESCAL8_SELECTED_CHECKS; do
        _ESCAL8_CURRENT_CHECK="$chk"
        _escal8_run_one_check "$chk"
        rc=$?
        _ESCAL8_CURRENT_CHECK=""

        if [ "$rc" -ne 0 ]; then
            ESCAL8_CHECK_STATUS[$chk]="failed"
            finding "FAILED" "internal.check_failed.$chk" \
                "Check module '$chk' exited unexpectedly (internal error, exit code $rc)" \
                "This indicates a bug in Escal8 itself, not a target misconfiguration. Results from this check may be incomplete - please report this."
        elif [ "${ESCAL8_CHECK_NONSKIP[$chk]:-0}" -gt 0 ]; then
            ESCAL8_CHECK_STATUS[$chk]="completed"
        else
            ESCAL8_CHECK_STATUS[$chk]="skipped"
        fi
    done

    escal8_print_summary
    escal8_print_check_coverage
    escal8_write_report

    # Exit code reflects worst finding severity, useful for CI/automation:
    # 2 = CRITICAL present, 1 = HIGH present, 0 = otherwise.
    if [ "${ESCAL8_COUNTS[CRITICAL]:-0}" -gt 0 ]; then
        exit 2
    elif [ "${ESCAL8_COUNTS[HIGH]:-0}" -gt 0 ]; then
        exit 1
    fi
    exit 0
}

escal8_main "$@"
