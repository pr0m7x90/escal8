# ------------------------------------------------------------------------------
# Summary + report generation
# ------------------------------------------------------------------------------

escal8_print_summary() {
    printf '\n%s=== Escal8 Summary ===%s\n' "${C_BOLD}${C_MAGENTA}" "$C_RESET"
    local sev
    for sev in CRITICAL HIGH MEDIUM LOW INFO OK SKIP FAILED; do
        local n="${ESCAL8_COUNTS[$sev]:-0}"
        local color; color="$(_escal8_sev_color "$sev")"
        printf '  %s%-8s%s : %s\n' "$color" "$sev" "$C_RESET" "$n"
    done

    local crit="${ESCAL8_COUNTS[CRITICAL]:-0}" high="${ESCAL8_COUNTS[HIGH]:-0}"
    if [ "$crit" -gt 0 ]; then
        printf '\n%s[!] %s CRITICAL finding(s) require immediate review.%s\n' "$C_RED$C_BOLD" "$crit" "$C_RESET"
    elif [ "$high" -gt 0 ]; then
        printf '\n%s[!] %s HIGH severity finding(s) worth reviewing.%s\n' "$C_YELLOW$C_BOLD" "$high" "$C_RESET"
    else
        printf '\n%s[+] No CRITICAL or HIGH severity findings in this run.%s\n' "$C_GREEN" "$C_RESET"
    fi
}

# escal8_print_check_coverage
# Prints which checks were completed, skipped (ran, but nothing could
# actually be assessed - every sub-item hit a missing tool), failed (an
# Escal8 bug, not a target finding), or simply not requested this run.
escal8_print_check_coverage() {
    [ "$ESCAL8_QUIET" -eq 1 ] && return 0
    printf '\n%s=== Check Coverage ===%s\n' "${C_BOLD}${C_MAGENTA}" "$C_RESET"

    local status label color c list
    for status in completed skipped failed unrequested; do
        case "$status" in
            completed)   label="Completed  "; color="$C_GREEN" ;;
            skipped)     label="Skipped    "; color="$C_DIM" ;;
            failed)      label="Failed     "; color="${C_MAGENTA}${C_BOLD}" ;;
            unrequested) label="Unrequested"; color="$C_DIM" ;;
        esac
        list=""
        for c in $ESCAL8_ALL_CHECKS; do
            [ "${ESCAL8_CHECK_STATUS[$c]:-unrequested}" = "$status" ] && list="$list $c"
        done
        list="$(printf '%s' "$list" | sed 's/^ //')"
        printf '  %s%s%s : %s\n' "$color" "$label" "$C_RESET" "${list:-(none)}"
    done
}

# _escal8_json_escape STRING
# Produces a JSON-string-safe version of STRING: escapes backslash and
# double-quote (structurally required), the named short escapes JSON
# defines for newline/CR/tab/backspace/form-feed, and any other control
# character (0x00-0x1F) as \u00XX, which the JSON spec requires - raw
# control bytes are not legal inside a JSON string. Pure bash, no awk/sed
# dependency, so it behaves identically regardless of which awk/sed happen
# to be on the target.
#
# Implementation note: the five named-escape substitutions below are plain
# O(1) bash parameter expansions, which is fast and sufficient for the
# overwhelming majority of finding text (paths, command output, config
# lines - none of which normally contain other control bytes). Order
# matters: backslash must be escaped FIRST, or the backslashes this
# function itself inserts for the other escapes would get double-escaped.
# A byte-by-byte scan (needed for arbitrary other control characters, e.g.
# a literal \x07 BEL byte some tool's output might contain) only runs if
# [[:cntrl:]] still matches after the cheap substitutions, so the common
# case never pays for it.
_escal8_json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    s="${s//$'\b'/\\b}"
    s="${s//$'\f'/\\f}"

    if [[ "$s" =~ [[:cntrl:]] ]]; then
        local out="" i c ord len
        local LC_ALL=C LC_CTYPE=C
        len=${#s}
        for (( i = 0; i < len; i++ )); do
            c="${s:i:1}"
            if [[ "$c" =~ [[:cntrl:]] ]]; then
                printf -v ord '%d' "'$c"
                out+="$(printf '\\u%04x' "$ord")"
            else
                out+="$c"
            fi
        done
        s="$out"
    fi

    printf '%s' "$s"
}

escal8_write_json() {
    local out="$1"
    {
        printf '{\n'
        printf '  "tool": "%s",\n' "$ESCAL8_NAME"
        printf '  "version": "%s",\n' "$ESCAL8_VERSION"
        printf '  "generated_at": "%s",\n' "$(human_time)"
        printf '  "profile": "%s",\n' "$ESCAL8_PROFILE"
        printf '  "counts": {\n'
        local first=1 sev
        for sev in CRITICAL HIGH MEDIUM LOW INFO OK SKIP FAILED; do
            [ "$first" -eq 1 ] || printf ',\n'
            first=0
            printf '    "%s": %s' "$sev" "${ESCAL8_COUNTS[$sev]:-0}"
        done
        printf '\n  },\n'
        printf '  "checks": {\n'
        local status c
        first=1
        for status in completed skipped failed unrequested; do
            [ "$first" -eq 1 ] || printf ',\n'
            first=0
            printf '    "%s": [' "$status"
            local first2=1
            for c in $ESCAL8_ALL_CHECKS; do
                [ "${ESCAL8_CHECK_STATUS[$c]:-unrequested}" = "$status" ] || continue
                [ "$first2" -eq 1 ] || printf ', '
                first2=0
                printf '"%s"' "$(_escal8_json_escape "$c")"
            done
            printf ']'
        done
        printf '\n  },\n'
        printf '  "findings": [\n'
        first=1
        while IFS='|' read -r sev id title detail; do
            [ -z "$sev" ] && continue
            [ "$first" -eq 1 ] || printf ',\n'
            first=0
            local dec; dec="$(_escal8_decode "$detail")"
            printf '    {"severity": "%s", "id": "%s", "title": "%s", "detail": "%s"}' \
                "$(_escal8_json_escape "$sev")" "$(_escal8_json_escape "$id")" \
                "$(_escal8_json_escape "$title")" "$(_escal8_json_escape "$dec")"
        done < "$ESCAL8_FINDINGS_FILE"
        printf '\n  ]\n'
        printf '}\n'
    } > "$out"
}

# _escal8_html_escape STRING
_escal8_html_escape() {
    printf '%s' "$1" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'
}

escal8_write_html() {
    local out="$1"
    {
        cat <<'HTMLHEAD'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Escal8 Report</title>
<style>
body{font-family:Consolas,Menlo,monospace;background:#111;color:#ddd;margin:2rem}
h1{color:#8ab4f8}
table{border-collapse:collapse;width:100%}
td,th{border:1px solid #333;padding:6px 10px;text-align:left;vertical-align:top}
th{background:#222}
.CRITICAL{background:#7a0000;color:#fff}
.HIGH{background:#5a2d00;color:#fff}
.MEDIUM{background:#5a4e00;color:#fff}
.LOW{color:#6cf}
.INFO{color:#8ab4f8}
.OK{color:#6c6}
.SKIP{color:#777}
.FAILED{background:#4a1a6a;color:#fff}
pre{white-space:pre-wrap;margin:0;font-size:0.9em}
</style>
</head>
<body>
HTMLHEAD
        printf '<h1>Escal8 v%s Report</h1>\n' "$ESCAL8_VERSION"
        printf '<p>Generated: %s &mdash; Profile: %s</p>\n' "$(human_time)" "$ESCAL8_PROFILE"

        printf '<h2>Check Coverage</h2>\n<ul>\n'
        local status c list
        for status in completed skipped failed unrequested; do
            list=""
            for c in $ESCAL8_ALL_CHECKS; do
                [ "${ESCAL8_CHECK_STATUS[$c]:-unrequested}" = "$status" ] && list="$list $c"
            done
            list="$(printf '%s' "$list" | sed 's/^ //')"
            printf '<li><b>%s</b>: %s</li>\n' "$(_escal8_html_escape "$status")" "$(_escal8_html_escape "${list:-(none)}")"
        done
        printf '</ul>\n'

        printf '<h2>Findings</h2>\n'
        printf '<table>\n<tr><th>Severity</th><th>Check ID</th><th>Title</th><th>Detail</th></tr>\n'
        while IFS='|' read -r sev id title detail; do
            [ -z "$sev" ] && continue
            local dec; dec="$(_escal8_decode "$detail")"
            printf '<tr class="%s"><td>%s</td><td>%s</td><td>%s</td><td><pre>%s</pre></td></tr>\n' \
                "$(_escal8_html_escape "$sev")" "$(_escal8_html_escape "$sev")" \
                "$(_escal8_html_escape "$id")" "$(_escal8_html_escape "$title")" \
                "$(_escal8_html_escape "$dec")"
        done < "$ESCAL8_FINDINGS_FILE"
        printf '</table>\n</body>\n</html>\n'
    } > "$out"
}

escal8_write_text_report() {
    local out="$1"
    {
        printf '%s v%s report - generated %s\n' "$ESCAL8_NAME" "$ESCAL8_VERSION" "$(human_time)"
        printf 'Profile: %s\n\n' "$ESCAL8_PROFILE"

        printf 'Check coverage:\n'
        local status c list
        for status in completed skipped failed unrequested; do
            list=""
            for c in $ESCAL8_ALL_CHECKS; do
                [ "${ESCAL8_CHECK_STATUS[$c]:-unrequested}" = "$status" ] && list="$list $c"
            done
            list="$(printf '%s' "$list" | sed 's/^ //')"
            printf '  %-12s: %s\n' "$status" "${list:-(none)}"
        done
        printf '\n'

        while IFS='|' read -r sev id title detail; do
            [ -z "$sev" ] && continue
            local dec; dec="$(_escal8_decode "$detail")"
            printf '[%s] %s - %s\n' "$sev" "$id" "$title"
            if [ -n "$dec" ]; then
                printf '%s\n' "$dec" | sed 's/^/    /'
            fi
            printf '\n'
        done < "$ESCAL8_FINDINGS_FILE"
    } > "$out"
}

escal8_write_report() {
    [ -z "$ESCAL8_OUTFILE" ] && return 0
    case "$ESCAL8_FORMAT" in
        json) escal8_write_json "$ESCAL8_OUTFILE" ;;
        html) escal8_write_html "$ESCAL8_OUTFILE" ;;
        *)    escal8_write_text_report "$ESCAL8_OUTFILE" ;;
    esac
    if [ "$ESCAL8_QUIET" -eq 0 ]; then
        printf '\n%s[+] Report written to %s (%s)%s\n' "$C_GREEN" "$ESCAL8_OUTFILE" "$ESCAL8_FORMAT" "$C_RESET"
    fi
}
