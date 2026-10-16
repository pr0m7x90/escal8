# ------------------------------------------------------------------------------
# Colors / styling
# ------------------------------------------------------------------------------
# Colors are enabled only when stdout is a tty and --no-color was not given.
# All color variables default to empty strings when disabled, so every print
# statement can unconditionally reference them without branching.

ESCAL8_NO_COLOR=0

_escal8_colors_init() {
    if [ "$ESCAL8_NO_COLOR" -eq 1 ] || [ ! -t 1 ] || [ -n "${NO_COLOR:-}" ]; then
        C_RESET=""; C_BOLD=""; C_DIM=""
        C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_MAGENTA=""; C_CYAN=""; C_WHITE=""
        C_BG_RED=""
        return
    fi
    C_RESET="$(printf '\033[0m')"
    C_BOLD="$(printf '\033[1m')"
    C_DIM="$(printf '\033[2m')"
    C_RED="$(printf '\033[31m')"
    C_GREEN="$(printf '\033[32m')"
    C_YELLOW="$(printf '\033[33m')"
    C_BLUE="$(printf '\033[34m')"
    C_MAGENTA="$(printf '\033[35m')"
    C_CYAN="$(printf '\033[36m')"
    C_WHITE="$(printf '\033[37m')"
    C_BG_RED="$(printf '\033[41m')"
}

# Severity -> color mapping, used by the finding interface and the summary.
_escal8_sev_color() {
    case "$1" in
        CRITICAL) printf '%s' "${C_BG_RED}${C_WHITE}${C_BOLD}" ;;
        HIGH)     printf '%s' "${C_RED}${C_BOLD}" ;;
        MEDIUM)   printf '%s' "${C_YELLOW}${C_BOLD}" ;;
        LOW)      printf '%s' "${C_CYAN}" ;;
        INFO)     printf '%s' "${C_BLUE}" ;;
        OK)       printf '%s' "${C_GREEN}" ;;
        SKIP)     printf '%s' "${C_DIM}" ;;
        FAILED)   printf '%s' "${C_MAGENTA}${C_BOLD}" ;;
        *)        printf '%s' "${C_WHITE}" ;;
    esac
}
