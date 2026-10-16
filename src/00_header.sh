#!/usr/bin/env bash
# ==============================================================================
# Escal8 - Linux Privilege Escalation Enumeration Tool
# ------------------------------------------------------------------------------
# Standalone, dependency-light Bash script for authorized security assessments
# (CTF, HTB/THM, pentest labs). Read-only enumeration only - this tool never
# attempts to escalate privileges, modify system state, or exploit anything.
#
# Generated from modular sources by build.sh - edit src/*.sh, not this file.
# ==============================================================================

# We require Bash itself (associative arrays, `local`, base#n arithmetic
# like $((16#ff)), [ "$x" ] tests, etc.) but deliberately avoid GNU-only
# coreutils flags throughout so the individual checks stay portable across
# BusyBox / musl / older GNU targets that a real assessment might land on.
if [ -z "${BASH_VERSION:-}" ]; then
    echo "Escal8 requires bash. Run it as: bash escal8.sh" >&2
    exit 1
fi

# Don't use 'set -e' - a single failed/absent command in a check must never
# abort the whole enumeration run. We handle errors locally per-check instead.
set -u
set -o pipefail 2>/dev/null || true

ESCAL8_VERSION="1.7.0-rc1"
ESCAL8_NAME="Escal8"
ESCAL8_START_EPOCH="$(date +%s 2>/dev/null || echo 0)"
