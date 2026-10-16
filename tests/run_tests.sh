#!/usr/bin/env bash
# Lightweight test harness for Escal8 that requires nothing beyond bash
# itself, so it runs in the same minimal environments Escal8 targets.
# For richer test authoring, see tests/escal8.bats (run with bats-core when
# available); the cases here are a portable equivalent subset.
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT_DIR/dist/escal8.sh"
TEST_TMP_BASE="$(mktemp -d)" || exit 1
trap 'rm -rf "$TEST_TMP_BASE"' EXIT
TEST_ERR="$TEST_TMP_BASE/test_err"
TEST_BARE_OUT="$TEST_TMP_BASE/bare_out"
TEST_BARE_ERR="$TEST_TMP_BASE/bare_err"
TESTS_RUN=0
TESTS_FAILED=0

pass() { printf '  [PASS] %s\n' "$1"; }
fail() { printf '  [FAIL] %s\n' "$1"; TESTS_FAILED=$((TESTS_FAILED+1)); }
check() {
    local desc="$1" cond="$2"
    TESTS_RUN=$((TESTS_RUN+1))
    if eval "$cond"; then pass "$desc"; else fail "$desc"; fi
}

echo "== Escal8 test suite =="
echo "Target: $SCRIPT"

if [ ! -x "$SCRIPT" ]; then
    echo "Build output not found or not executable: $SCRIPT" >&2
    echo "Run ./build.sh first." >&2
    exit 1
fi

# The shebang must be the literal first two bytes of the file, or the
# kernel won't honor it at all and silently falls back to /bin/sh for
# direct (`./dist/escal8.sh`) execution - which then hits Escal8's own
# "requires bash" guard. A blank line or comment before it (e.g. a
# module-boundary marker from the build process) breaks this silently.
check "dist/escal8.sh's shebang is the literal first line (fix #4 regression)" \
    "[ \"\$(head -c 2 '$SCRIPT')\" = '#!' ]"
out="$("$SCRIPT" --version 2>&1)"; rc=$?
check "dist/escal8.sh can be executed directly (./escal8.sh), not just via 'bash escal8.sh'" \
    "[ $rc -eq 0 ] && printf '%s' \"\$out\" | grep -q 'Escal8 v'"

# --- --help ---------------------------------------------------------------
out="$("$SCRIPT" --help 2>&1)"; rc=$?
check "--help exits 0" "[ $rc -eq 0 ]"
check "--help mentions USAGE" "printf '%s' \"\$out\" | grep -q 'USAGE:'"
check "--help documents --profile" "printf '%s' \"\$out\" | grep -q -- '--profile'"

# --- --version --------------------------------------------------------------
out="$("$SCRIPT" --version 2>&1)"; rc=$?
check "--version exits 0" "[ $rc -eq 0 ]"
check "--version prints Escal8" "printf '%s' \"\$out\" | grep -q 'Escal8'"

# --- --list-checks ----------------------------------------------------------
out="$("$SCRIPT" --list-checks 2>&1)"; rc=$?
check "--list-checks exits 0" "[ $rc -eq 0 ]"
check "--list-checks lists suid" "printf '%s' \"\$out\" | grep -q 'suid'"
check "--list-checks lists kernel" "printf '%s' \"\$out\" | grep -q 'kernel'"

check "--list-checks includes ACL review" "printf '%s' \"\$out\" | grep -q 'acl'"
check "--list-checks includes sudo token metadata review" "printf '%s' \"\$out\" | grep -q 'sudotokens'"
check "--list-checks includes mount review" "printf '%s' \"\$out\" | grep -q 'mounts'"
check "--list-checks includes software inventory" "printf '%s' \"\$out\" | grep -q 'software'"
check "--list-checks includes cloud identity review" "printf '%s' \"\$out\" | grep -q 'cloud'"
check "--list-checks includes DevOps surface review" "printf '%s' \"\$out\" | grep -q 'devops'"

# New modules must dispatch independently and must not create internal FAILED findings.
for newcheck in acl sudotokens mounts software systemd_timers polkit kernel_hardening deleted_files cloud devops system_surfaces; do
    newout="$TEST_TMP_BASE/newcheck_$newcheck"
    "$SCRIPT" --no-color --checks "$newcheck" --format json --output "$TEST_TMP_BASE/newcheck_$newcheck.json" >"$newout" 2>&1
    rc=$?
    check "$newcheck check dispatches without a shell/internal error" "[ $rc -le 2 ] && ! grep -q 'check_failed\.$newcheck' '$newout'"
    check "$newcheck check appears in JSON report" "grep -q '\"$newcheck\"' '$TEST_TMP_BASE/newcheck_$newcheck.json'"
done


# --- invalid input handling --------------------------------------------------
"$SCRIPT" --profile bogus >/dev/null 2>$TEST_ERR; rc=$?
check "invalid --profile exits 2" "[ $rc -eq 2 ]"
check "invalid --profile reports error on stderr" "grep -q 'unknown profile' $TEST_ERR"

"$SCRIPT" --format xml >/dev/null 2>$TEST_ERR; rc=$?
check "invalid --format exits 2" "[ $rc -eq 2 ]"

"$SCRIPT" --not-a-real-flag >/dev/null 2>$TEST_ERR; rc=$?
check "unknown flag exits 2" "[ $rc -eq 2 ]"

# A finding raised from a process loop must update the parent shell's counters
# and exit code. This regression runs only as non-root, because the check is
# intentionally skipped when Escal8 itself is root.
if [ "$(id -u)" -ne 0 ]; then
    services_reg_dir="$TEST_TMP_BASE/services-pipeline-regression"
    mkdir -p "$services_reg_dir/mockbin"
    chmod 755 "$services_reg_dir" "$services_reg_dir/mockbin"
    services_reg_script="$services_reg_dir/root-task.sh"
    printf '#!/bin/sh\nexit 0\n' > "$services_reg_script"
    chmod 666 "$services_reg_script"
    cat > "$services_reg_dir/mockbin/ps" <<'MOCKPS'
#!/bin/sh
printf 'UID PID PPID C STIME TTY TIME CMD\n'
printf 'root 1 0 0 ? 00:00:00 %s\n' "$ESCAL8_TEST_SCRIPT"
MOCKPS
    chmod +x "$services_reg_dir/mockbin/ps"
    services_reg_out="$services_reg_dir/output.txt"
    services_reg_json="$services_reg_dir/report.json"
    ESCAL8_TEST_SCRIPT="$services_reg_script" PATH="$services_reg_dir/mockbin:/usr/bin:/bin" \
        "$SCRIPT" --no-color --checks services --format json --output "$services_reg_json" >"$services_reg_out" 2>&1
    rc=$?
    check "writable root-process script finding updates CRITICAL count and exit code" \
        "[ $rc -eq 2 ] && grep -q 'CRITICAL *: 1' '$services_reg_out' && grep -q '\"CRITICAL\": 1' '$services_reg_json'"
else
    echo '  [SKIP] writable root-process counter regression (requires non-root execution)'
fi

# --- privilege-escalation heuristic severity regressions ----------------------
# A NOPASSWD rule is not automatically exploitable; verify it is not promoted
# to HIGH solely because the tag appears in sudo -l output.
sudo_mock_dir="$(mktemp -d)"
cat > "$sudo_mock_dir/sudo" <<'MOCKSUDO'
#!/bin/sh
case "$*" in
    "-n -l") printf '%s\n' "(ALL) NOPASSWD: /usr/bin/id" ;;
    "-V") printf '%s\n' "Sudo version 1.9.15" ;;
    *) exit 1 ;;
esac
MOCKSUDO
chmod +x "$sudo_mock_dir/sudo"
sudo_mock_out="$(mktemp)"
PATH="$sudo_mock_dir:/usr/bin:/bin" "$SCRIPT" --no-color --checks sudo >"$sudo_mock_out" 2>&1
check "NOPASSWD alone is reported as INFO, not HIGH" \
    "grep -q '\\[INFO[[:space:]]*\\].*User has one or more NOPASSWD sudo entries' '$sudo_mock_out' && ! grep -q '\\[HIGH[[:space:]]*\\].*User has one or more NOPASSWD sudo entries' '$sudo_mock_out'"
rm -rf "$sudo_mock_dir" "$sudo_mock_out"

# Risky-command detection must match an actual sudo command entry, not just
# a binary name in explanatory text.
sudo_risk_dir="$(mktemp -d)"
cat > "$sudo_risk_dir/sudo" <<'MOCKSUDO'
#!/bin/sh
case "$*" in
    "-n -l") printf '%s\n' "User may run the following commands on host:" "    (root) /usr/bin/vim" ;;
    "-V") printf '%s\n' "Sudo version 1.9.15" ;;
    *) exit 1 ;;
esac
MOCKSUDO
chmod +x "$sudo_risk_dir/sudo"
sudo_risk_out="$sudo_risk_dir/output"
PATH="$sudo_risk_dir:/usr/bin:/bin" "$SCRIPT" --no-color --checks sudo >"$sudo_risk_out" 2>&1
check "sudo risky-binary heuristic matches an actual allowed command entry" \
    "grep -q 'sudo command entry matches commonly abusable program' '$sudo_risk_out'"
rm -rf "$sudo_risk_dir"

# A risky command permitted only as a named non-root account must not be
# presented as a HIGH root-escalation candidate.
sudo_nonroot_dir="$(mktemp -d)"
cat > "$sudo_nonroot_dir/sudo" <<'MOCKSUDO'
#!/bin/sh
case "$*" in
    "-n -l") printf '%s\n' "User may run the following commands on host:" "    (daemon) NOPASSWD: /usr/bin/vim" ;;
    "-V") printf '%s\n' "Sudo version 1.9.15" ;;
    *) exit 1 ;;
esac
MOCKSUDO
chmod +x "$sudo_nonroot_dir/sudo"
sudo_nonroot_out="$sudo_nonroot_dir/output"
PATH="$sudo_nonroot_dir:/usr/bin:/bin" "$SCRIPT" --no-color --checks sudo >"$sudo_nonroot_out" 2>&1
check "risky sudo binary allowed only as named non-root user is not HIGH" \
    "! grep -q 'sudo command entry matches commonly abusable program' '$sudo_nonroot_out'"
rm -rf "$sudo_nonroot_dir"

# ALL run-as remains eligible for a HIGH heuristic because root may be selected.
sudo_all_dir="$(mktemp -d)"
cat > "$sudo_all_dir/sudo" <<'MOCKSUDO'
#!/bin/sh
case "$*" in
    "-n -l") printf '%s\n' "User may run the following commands on host:" "    (ALL : ALL) NOPASSWD: /usr/bin/vim" ;;
    "-V") printf '%s\n' "Sudo version 1.9.15" ;;
    *) exit 1 ;;
esac
MOCKSUDO
chmod +x "$sudo_all_dir/sudo"
sudo_all_out="$sudo_all_dir/output"
PATH="$sudo_all_dir:/usr/bin:/bin" "$SCRIPT" --no-color --checks sudo >"$sudo_all_out" 2>&1
check "sudo risky-binary heuristic handles (ALL : ALL) run-as syntax" \
    "grep -q 'Root/ALL sudo command entry matches commonly abusable program' '$sudo_all_out'"
rm -rf "$sudo_all_dir"

# For a non-root run, verify a root-authorized command path writable by the
# current user is reported, while NOPASSWD alone remains informational.
if [ "$(id -u)" -ne 0 ]; then
    sudo_write_dir="$(mktemp -d)"
    sudo_write_file="$sudo_write_dir/allowed-script"
    printf '#!/bin/sh\nexit 0\n' > "$sudo_write_file"
    chmod 755 "$sudo_write_file"
    sudo_write_mock="$sudo_write_dir/mockbin"
    mkdir -p "$sudo_write_mock"
    cat > "$sudo_write_mock/sudo" <<MOCKSUDO
#!/bin/sh
case "\$*" in
    "-n -l") printf '%s\n' "(root) NOPASSWD: $sudo_write_file" ;;
    "-V") printf '%s\n' "Sudo version 1.9.15" ;;
    *) exit 1 ;;
esac
MOCKSUDO
    chmod +x "$sudo_write_mock/sudo"
    sudo_write_out="$sudo_write_dir/output"
    PATH="$sudo_write_mock:/usr/bin:/bin" "$SCRIPT" --no-color --checks sudo >"$sudo_write_out" 2>&1
    check "root-authorized sudo command writable by current user is HIGH" \
        "grep -q '\\[HIGH[[:space:]]*\\].*Sudo-allowed command is writable by the current user' '$sudo_write_out'"
    rm -rf "$sudo_write_dir"
else
    echo '  [SKIP] sudo writable-command test (requires non-root execution)'
fi

# Mock find output to ensure a risky SUID name is treated as a heuristic,
# not automatically as a HIGH/CRITICAL vulnerability without contextual evidence.
suid_mock_dir="$(mktemp -d)"
suid_mock_bin="$suid_mock_dir/vim"
printf '#!/bin/sh\nexit 0\n' > "$suid_mock_bin"
chmod 4755 "$suid_mock_bin" 2>/dev/null || chmod 755 "$suid_mock_bin"
cat > "$suid_mock_dir/find" <<'MOCKFIND'
#!/bin/sh
case "$*" in
    *"-perm -4000"*) printf '%s\n' "$SUID_MOCK_BIN"; exit 1 ;;
    *"-perm -2000"*) : ;;
    *) : ;;
esac
MOCKFIND
chmod +x "$suid_mock_dir/find"
suid_mock_out="$(mktemp)"
SUID_MOCK_BIN="$suid_mock_bin" PATH="$suid_mock_dir:/usr/bin:/bin" "$SCRIPT" --no-color --checks suid >"$suid_mock_out" 2>&1
check "SUID risky-name heuristic is MEDIUM, not HIGH/CRITICAL without context" \
    "grep -q '\\[MEDIUM[[:space:]]*\\].*SUID binary matches a commonly abusable program' '$suid_mock_out' && ! grep -qE '\\[(HIGH|CRITICAL)[[:space:]]*\\].*SUID binary matches a commonly abusable program' '$suid_mock_out'"
check "SUID scan with usable results and find error is reported as partial, not skipped" \
    "grep -q 'SUID/SGID scan was partial; results were collected' '$suid_mock_out' && ! grep -q 'SUID/SGID scan returned an error and no results' '$suid_mock_out'"
rm -rf "$suid_mock_dir" "$suid_mock_out"

# Root-owned writable executable scan should report a writable candidate
# for non-root users. Mock find to make the test deterministic and fast.
if [ "$(id -u)" -ne 0 ]; then
    writable_exec_dir="$(mktemp -d)"
    writable_exec_file="$writable_exec_dir/candidate"
    printf '#!/bin/sh\nexit 0\n' > "$writable_exec_file"
    chmod 755 "$writable_exec_file"
    writable_exec_mock="$writable_exec_dir/mockbin"
    mkdir -p "$writable_exec_mock"
    cat > "$writable_exec_mock/find" <<MOCKFIND
#!/bin/sh
case "\$*" in
    *"-user root"*) printf '%s\\n' "$writable_exec_file" ;;
    *) : ;;
esac
MOCKFIND
    chmod +x "$writable_exec_mock/find"
    writable_exec_out="$writable_exec_dir/output"
    PATH="$writable_exec_mock:/usr/bin:/bin" "$SCRIPT" --no-color --checks writable >"$writable_exec_out" 2>&1
    check "writable root-owned executable candidate is surfaced as HIGH" \
        "grep -q '\\[HIGH[[:space:]]*\\].*Root-owned executable is writable by the current user' '$writable_exec_out'"
    rm -rf "$writable_exec_dir"

    # A partial find scan must preserve candidates already emitted and disclose
    # that inaccessible paths may have been missed.
    partial_dir="$(mktemp -d)"
    partial_file="$partial_dir/candidate"
    printf '#!/bin/sh\nexit 0\n' > "$partial_file"
    chmod 755 "$partial_file"
    partial_mock="$partial_dir/mockbin"
    mkdir -p "$partial_mock"
    cat > "$partial_mock/find" <<MOCKFIND
#!/bin/sh
case "\$*" in
    *"-user root"*)
        printf '%s\n' "$partial_file"
        echo "fixture: Permission denied" >&2
        exit 1
        ;;
    *) exit 0 ;;
esac
MOCKFIND
    chmod +x "$partial_mock/find"
    partial_out="$partial_dir/output"
    PATH="$partial_mock:/usr/bin:/bin" "$SCRIPT" --no-color --checks writable >"$partial_out" 2>&1
    check "partial writable scan preserves and reports discovered candidate" \
        "grep -Fq 'Root-owned executable is writable by the current user:' '$partial_out' && grep -Fq 'Root-owned executable scan was partial' '$partial_out'"
    rm -rf "$partial_dir"
else
    echo '  [SKIP] writable root-owned executable candidate test (requires non-root execution)'
fi

# --- new coverage checks and secret redaction -------------------------------
out="$($SCRIPT --no-color --checks processes 2>&1)"
check "processes check dispatches and prints its section" "printf '%s' \"\$out\" | grep -q 'Privileged Process Paths'"
out="$($SCRIPT --no-color --checks credentials 2>&1)"
check "credentials check dispatches and prints its section" "printf '%s' \"\$out\" | grep -q 'Potential Credential Files'"
out="$(API_KEY=escal8-test-secret-value "$SCRIPT" --no-color --checks historyenv 2>&1)"
check "environment secret names are reported with values redacted" "printf '%s' \"\$out\" | grep -q 'API_KEY=<redacted>'"
check "environment secret values are not leaked into findings" "! printf '%s' \"\$out\" | grep -q 'escal8-test-secret-value'"


# Cloud checks must report variable names without leaking values, and must
# identify obviously world-readable provider credential paths from metadata only.
cloud_tmp="$(mktemp -d)"
mkdir -p "$cloud_tmp/.aws"
printf '%s\n' 'NEVER_PRINT_THIS_SECRET' > "$cloud_tmp/.aws/credentials"
chmod 644 "$cloud_tmp/.aws/credentials"
cloud_out="$cloud_tmp/cloud-output.txt"
HOME="$cloud_tmp" AWS_SECRET_ACCESS_KEY='escal8-cloud-secret-sentinel' "$SCRIPT" --no-color --checks cloud > "$cloud_out" 2>&1
check "cloud check reports variable names without leaking secret values" \
    "grep -q 'AWS_SECRET_ACCESS_KEY' '$cloud_out' && ! grep -q 'escal8-cloud-secret-sentinel' '$cloud_out'"
check "cloud check flags world-readable credential path from metadata" \
    "grep -q 'Cloud/deployment credential configuration is world-readable' '$cloud_out'"
check "cloud check never prints fixture file contents" \
    "! grep -q 'NEVER_PRINT_THIS_SECRET' '$cloud_out'"
rm -rf "$cloud_tmp"

# DevOps checks are metadata-only and should never execute runtime sockets.
out="$($SCRIPT --no-color --checks devops 2>&1)"
check "DevOps surface check dispatches and prints its section" \
    "printf '%s' \"\$out\" | grep -q 'DevOps and Orchestration Surfaces'"

# --- selective checks ---------------------------------------------------------
out="$("$SCRIPT" --no-color --checks system --quiet 2>&1)"
check "--checks system runs only System Information" "printf '%s' \"\$out\" | grep -qv 'Sudo Configuration' "
# Run without --quiet to confirm section header shows and others don't.
out="$("$SCRIPT" --no-color --checks system 2>&1)"
check "--checks system shows System Information section" "printf '%s' \"\$out\" | grep -q 'System Information'"
check "--checks system omits SUID section" "! printf '%s' \"\$out\" | grep -q 'SUID / SGID Binaries'"

# --- quiet mode ----------------------------------------------------------------
out="$("$SCRIPT" --no-color --checks system --quiet 2>&1)"
check "quiet mode suppresses INFO lines" "! printf '%s' \"\$out\" | grep -q '\[INFO'"
check "quiet mode still prints summary" "printf '%s' \"\$out\" | grep -q 'Escal8 Summary'"

# --- JSON report -----------------------------------------------------------
tmpjson="$(mktemp)"
"$SCRIPT" --no-color --checks system,kernel --quiet --format json --output "$tmpjson" >/dev/null 2>&1
check "JSON report file created" "[ -s \"$tmpjson\" ]"
if command -v python3 >/dev/null 2>&1; then
    check "JSON report parses as valid JSON" "python3 -c \"import json; json.load(open('$tmpjson'))\" >/dev/null 2>&1"
else
    check "JSON report has balanced braces (python3 unavailable for strict parse)" \
        "[ \"\$(tr -cd '{' < \"$tmpjson\" | wc -c)\" = \"\$(tr -cd '}' < \"$tmpjson\" | wc -c)\" ]"
fi
rm -f "$tmpjson"

# --- HTML report -----------------------------------------------------------
tmphtml="$(mktemp)"
"$SCRIPT" --no-color --checks system --quiet --format html --output "$tmphtml" >/dev/null 2>&1
check "HTML report file created" "[ -s \"$tmphtml\" ]"
check "HTML report has closing </html>" "grep -q '</html>' \"$tmphtml\""
check "HTML report has a table" "grep -q '<table>' \"$tmphtml\""
rm -f "$tmphtml"

# --- text report -------------------------------------------------------------
tmptxt="$(mktemp)"
"$SCRIPT" --no-color --checks system --quiet --output "$tmptxt" >/dev/null 2>&1
check "text report file created" "[ -s \"$tmptxt\" ]"
check "text report mentions tool name" "grep -q 'Escal8' \"$tmptxt\""
rm -f "$tmptxt"

# --- unit tests: secure temp directory (fix #1) --------------------------------
# These source the relevant modules directly rather than the bundled
# dist/escal8.sh, since the bundle runs escal8_main() immediately on load -
# sourcing the individual src/ files lets us call the helper functions in
# isolation with controlled, disposable fixtures instead.
UTILS_SRC="$ROOT_DIR/src/02_utils.sh"
COLORS_SRC="$ROOT_DIR/src/01_colors.sh"

unit_tmp_base="$(mktemp -d)"
out="$(bash -c '
    source "'"$COLORS_SRC"'"
    source "'"$UTILS_SRC"'"
    _escal8_colors_init
    d="$(escal8_secure_tmpdir)"
    rc=$?
    echo "DIR=$d"
    echo "RC=$rc"
' 2>&1)"
secdir="$(printf '%s\n' "$out" | sed -n 's/^DIR=//p')"
secrc="$(printf '%s\n' "$out" | sed -n 's/^RC=//p')"
check "escal8_secure_tmpdir succeeds and returns a path" "[ \"$secrc\" = '0' ] && [ -n \"$secdir\" ]"
check "escal8_secure_tmpdir's directory is NOT a predictable /tmp/.escal8_\$\$-style name" \
    "! printf '%s' \"$secdir\" | grep -qE '^\.?/tmp/\.escal8_[0-9]+\$'"
if [ -n "$secdir" ] && [ -d "$secdir" ]; then
    mode="$(stat -c '%a' "$secdir" 2>/dev/null)"
    check "escal8_secure_tmpdir's directory is mode 700" "[ \"$mode\" = '700' ]"
    owner="$(stat -c '%u' "$secdir" 2>/dev/null)"
    check "escal8_secure_tmpdir's directory is owned by the current EUID" "[ \"$owner\" = \"$(id -u)\" ]"
    rm -rf "$secdir"
fi

# Symlink pre-creation attack: if an attacker has already planted a
# symlink (or a file, or a directory) at a candidate path, _escal8_mkdir_secure
# must refuse to reuse it rather than writing through/into it.
preexisting="$unit_tmp_base/preexisting_target"
attacker_symlink="$unit_tmp_base/attacker_link"
mkdir -p "$preexisting"
ln -s "$preexisting" "$attacker_symlink"
out="$(bash -c '
    source "'"$UTILS_SRC"'"
    _escal8_mkdir_secure "'"$attacker_symlink"'"
    echo "RC=$?"
')"
rc="$(printf '%s\n' "$out" | sed -n 's/^RC=//p')"
check "_escal8_mkdir_secure refuses to reuse a pre-existing symlink (fails, does not follow it)" "[ \"$rc\" != '0' ]"
check "the pre-existing symlink's target is untouched by the refused attempt" "[ -d \"$preexisting\" ] && [ -z \"\$(ls -A \"$preexisting\" 2>/dev/null)\" ]"

# _escal8_verify_secure_dir must reject a symlink even if one somehow got
# passed in, and must reject a directory it doesn't own.
out="$(bash -c '
    source "'"$UTILS_SRC"'"
    _escal8_verify_secure_dir "'"$attacker_symlink"'"
    echo "RC=$?"
')"
rc="$(printf '%s\n' "$out" | sed -n 's/^RC=//p')"
check "_escal8_verify_secure_dir rejects a symlink" "[ \"$rc\" != '0' ]"

if [ "$(id -u)" = "0" ] && command -v chown >/dev/null 2>&1 && id nobody >/dev/null 2>&1; then
    foreign_dir="$unit_tmp_base/foreign_owned"
    mkdir -p "$foreign_dir"
    chmod 700 "$foreign_dir"
    chown nobody "$foreign_dir" 2>/dev/null
    out="$(bash -c '
        source "'"$UTILS_SRC"'"
        _escal8_verify_secure_dir "'"$foreign_dir"'"
        echo "RC=$?"
    ')"
    rc="$(printf '%s\n' "$out" | sed -n 's/^RC=//p')"
    check "_escal8_verify_secure_dir rejects a directory it doesn't own, even if mode 700 (as root, DAC bypass would otherwise hide this)" "[ \"$rc\" != '0' ]"
fi
rm -rf "$unit_tmp_base"

# Full end-to-end: a real run must leave no temp directory behind on exit.
before_count="$(find "${TMPDIR:-/tmp}" -maxdepth 1 -name '.escal8.*' -o -name 'escal8.*' 2>/dev/null | wc -l)"
"$SCRIPT" --no-color --checks system --quiet >/dev/null 2>&1
after_count="$(find "${TMPDIR:-/tmp}" -maxdepth 1 -name '.escal8.*' -o -name 'escal8.*' 2>/dev/null | wc -l)"
check "no leftover escal8 temp directory after a normal run" "[ \"$before_count\" = \"$after_count\" ]"

# --- unit tests: root-aware permission checks (fix #2) -------------------------
PERMTEST_SRC="$UTILS_SRC"
perm_tmp="$(mktemp -d)"
sensitive_like="$perm_tmp/sensitive_file"
echo "test" > "$sensitive_like"

chmod 640 "$sensitive_like"
if [ "$(id -u)" = 0 ]; then
    out="$(bash -c '
        source "'"$PERMTEST_SRC"'"
        escal8_effective_access "'"$sensitive_like"'" r
        echo "R=$?"
        escal8_effective_access "'"$sensitive_like"'" w
        echo "W=$?"
    ')"
    r_rc="$(printf '%s\n' "$out" | sed -n 's/^R=//p')"
    w_rc="$(printf '%s\n' "$out" | sed -n 's/^W=//p')"
    check "mode 640 file: root-aware helper reports NOT other-readable" "[ \"$r_rc\" = '1' ]"
    check "mode 640 file: root-aware helper reports NOT other-writable" "[ \"$w_rc\" = '1' ]"
else
    echo '  [SKIP] mode 640 root-DAC permission tests (run suite as root to exercise)'
fi

chmod 666 "$sensitive_like"
out="$(bash -c '
    source "'"$PERMTEST_SRC"'"
    escal8_effective_access "'"$sensitive_like"'" r
    echo "R=$?"
    escal8_effective_access "'"$sensitive_like"'" w
    echo "W=$?"
')"
r_rc="$(printf '%s\n' "$out" | sed -n 's/^R=//p')"
w_rc="$(printf '%s\n' "$out" | sed -n 's/^W=//p')"
check "mode 666 (genuinely misconfigured) file: escal8_effective_access (as root) reports readable" "[ \"$r_rc\" = '0' ]"
check "mode 666 (genuinely misconfigured) file: escal8_effective_access (as root) reports writable" "[ \"$w_rc\" = '0' ]"

# Root-specific checks validate generic-user permissions rather than the
# invoking user's own access. Skip them explicitly in an unprivileged run.
if [ "$(id -u)" = 0 ]; then
    real_dir="$perm_tmp/real_dir"
    link_dir="$perm_tmp/link_dir"
    mkdir -p "$real_dir"
    chmod 755 "$real_dir"
    ln -s "$real_dir" "$link_dir"
    out="$(bash -c '
        source "'"$PERMTEST_SRC"'"
        escal8_effective_access "'"$link_dir"'" w
        echo "W=$?"
    ')"
    w_rc="$(printf '%s\n' "$out" | sed -n 's/^W=//p')"
    check "symlink to mode-755 directory is NOT other-writable" "[ \"$w_rc\" = '1' ]"
else
    echo '  [SKIP] symlink other-permission test (run suite as root to exercise)'
fi
rm -rf "$perm_tmp"

if [ "$(id -u)" = 0 ]; then
    out="$(PATH=/usr/bin:/bin "$SCRIPT" --no-color --checks path --quiet 2>&1)"
    check "end-to-end root PATH check: standard system PATH has no false-positive CRITICALs" \
        "printf '%s' \"\$out\" | grep -q 'CRITICAL : 0'"
else
    echo '  [SKIP] root end-to-end permission regression (run suite as root to exercise)'
fi

# --- unit tests: JSON escaping (fix #3) -----------------------------------------
REPORT_SRC="$ROOT_DIR/src/90_report.sh"
PYCHECK_SCRIPT="$(mktemp)"
cat > "$PYCHECK_SCRIPT" <<'PYEOF'
import json, sys
with open(sys.argv[1]) as f:
    d = json.load(f)
with open(sys.argv[2], 'rb') as f:
    expected = f.read().decode('utf-8')
sys.exit(0 if d['v'] == expected else 1)
PYEOF

# Passes the expected value through FILES (read via argv paths), not
# through shell/eval string interpolation: json_escape_case's input can
# contain quotes, backslashes, and control characters, any of which would
# corrupt a condition string built for check()'s later `eval` if embedded
# directly. Files sidestep that entirely.
json_escape_case() {
    local desc="$1" input="$2"
    local escaped expectedfile jsonfile
    escaped="$(bash -c '
        source "'"$REPORT_SRC"'"
        _escal8_json_escape "$1"
    ' _ "$input")"
    jsonfile="$(mktemp)"
    expectedfile="$(mktemp)"
    printf '{"v": "%s"}' "$escaped" > "$jsonfile"
    printf '%s' "$input" > "$expectedfile"
    if command -v python3 >/dev/null 2>&1; then
        check "$desc" "python3 '$PYCHECK_SCRIPT' '$jsonfile' '$expectedfile'"
    else
        check "$desc (brace-balance check only, python3 unavailable)" \
            "[ \"\$(tr -cd '{' < '$jsonfile' | wc -c)\" = \"\$(tr -cd '}' < '$jsonfile' | wc -c)\" ]"
    fi
    rm -f "$jsonfile" "$expectedfile"
}
json_escape_case "JSON escape: double quote" 'say "hi"'
json_escape_case "JSON escape: backslash" 'C:\Windows\System32'
json_escape_case "JSON escape: tab" "$(printf 'a\tb')"
json_escape_case "JSON escape: carriage return" "$(printf 'a\rb')"
json_escape_case "JSON escape: bell control char" "$(printf 'a\x07b')"
json_escape_case "JSON escape: unit separator control char" "$(printf 'a\x1fb')"
rm -f "$TEST_TMP_BASE/escal8_jsontest.json"

# Multi-line detail (the common real-world case: encode -> decode -> JSON
# escape, exactly as the report generator actually does it) must also
# round-trip through a real JSON parser.
multiline_detail="$(printf 'line one "quoted"\tline two\\with\\backslashes')"
if command -v python3 >/dev/null 2>&1; then
    tmpjson2="$(mktemp)"
    expectedfile2="$(mktemp)"
    out="$(bash -c '
        source "'"$REPORT_SRC"'"
        source "'"$UTILS_SRC"'"
        enc="$(_escal8_encode "$1")"
        dec="$(_escal8_decode "$enc")"
        _escal8_json_escape "$dec"
    ' _ "$multiline_detail")"
    printf '{"v": "%s"}' "$out" > "$tmpjson2"
    printf '%s' "$multiline_detail" > "$expectedfile2"
    check "JSON escape: full encode->decode->escape pipeline round-trips through a real parser" \
        "python3 '$PYCHECK_SCRIPT' '$tmpjson2' '$expectedfile2'"
    rm -f "$tmpjson2" "$expectedfile2"
fi
rm -f "$PYCHECK_SCRIPT"

# --- unit tests: --checks validation and check coverage (fix #5) ---------------
out="$("$SCRIPT" --checks system,totally_bogus_check --no-color 2>&1)"; rc=$?
check "unknown --checks name is rejected with exit code 2" "[ $rc -eq 2 ]"
check "unknown --checks name is named in the error message" "printf '%s' \"\$out\" | grep -q 'totally_bogus_check'"
check "unknown --checks name: NO checks are silently run (banner never printed)" \
    "! printf '%s' \"\$out\" | grep -q 'Linux Privilege Escalation Enumeration'"

out="$("$SCRIPT" --checks kernel,another_bogus_one,suid --no-color 2>&1)"; rc=$?
check "unknown --checks name mixed with valid ones is still rejected wholesale" "[ $rc -eq 2 ]"

out="$("$SCRIPT" --no-color --checks system,kernel 2>&1)"
check "check coverage section is printed" "printf '%s' \"\$out\" | grep -q 'Check Coverage'"
check "check coverage: requested+assessed checks show as Completed" "printf '%s' \"\$out\" | grep -E '^\s*Completed' | grep -q 'system' "
check "check coverage: non-selected checks show as Unrequested" "printf '%s' \"\$out\" | grep -E '^\s*Unrequested' | grep -q 'suid'"
check "check coverage: non-selected checks are NOT listed as Completed" "! printf '%s' \"\$out\" | grep -E '^\s*Completed' | grep -q 'suid'"

# Module-level "skipped" (ran, but could assess nothing - distinct from a
# sub-finding SKIP, and distinct from simply not being requested at all).
mintools_dir2="$(mktemp -d)"
for b in bash cat grep sed awk sort uniq head tail tr wc date ps id hostname uname basename dirname mkdir; do
    p="$(command -v "$b" 2>/dev/null)"
    [ -n "$p" ] && ln -sf "$p" "$mintools_dir2/$b"
done
out="$(PATH="$mintools_dir2" "$SCRIPT" --no-color --checks sudo,suid,system 2>&1)"
check "check coverage: a check with its only tool missing shows as Skipped, not Completed" \
    "printf '%s' \"\$out\" | grep -E '^\s*Skipped' | grep -q 'sudo' && printf '%s' \"\$out\" | grep -E '^\s*Skipped' | grep -q 'suid'"
check "check coverage: a check that actually found something is Completed, not Skipped" \
    "printf '%s' \"\$out\" | grep -E '^\s*Completed' | grep -q 'system'"
rm -rf "$mintools_dir2"

# A check module that exits with a nonzero status must be classified
# FAILED (an Escal8 bug), separately from the target-vulnerability
# severities, and must not be silently treated as a clean "Completed" run.
faildir="$(mktemp -d)"
cp "$SCRIPT" "$faildir/escal8.sh"
sed -i 's/system)       run_check_system ;;/system)       run_check_system; return 1 ;;/' "$faildir/escal8.sh"
out="$(bash "$faildir/escal8.sh" --no-color --checks system,kernel 2>&1)"
check "check coverage: a check module that exits non-zero is classified Failed" \
    "printf '%s' \"\$out\" | grep -E '^\s*Failed' | grep -q 'system'"
check "a failed check module produces a visible FAILED finding, not silence" "printf '%s' \"\$out\" | grep -q \"Check module 'system' exited unexpectedly\""
check "FAILED count appears in the summary" "printf '%s' \"\$out\" | grep -qE 'FAILED\s*: 1'"
rm -rf "$faildir"

# --- exit code reflects severity ---------------------------------------------
# Craft a synthetic, disposable fixture directory that is world-writable and
# inject it into PATH to deterministically trigger a CRITICAL path.writable
# finding, independent of whatever the host environment looks like.
fixture_dir="$(mktemp -d)"
chmod 777 "$fixture_dir"
PATH="$fixture_dir:$PATH" "$SCRIPT" --no-color --checks path --quiet >/dev/null 2>&1
rc=$?
check "synthetic writable PATH dir yields CRITICAL exit code (2)" "[ $rc -eq 2 ]"
rmdir "$fixture_dir" 2>/dev/null

# A directory owned by the invoking user with mode 755 is writable by that
# user, but not by other unprivileged users; it must not trigger path.writable.
own_path_dir="$(mktemp -d)"
chmod 755 "$own_path_dir"
PATH="$own_path_dir:/usr/bin:/bin" "$SCRIPT" --no-color --checks path --quiet >/dev/null 2>&1
rc=$?
check "user-owned mode-755 PATH directory does not trigger a false-positive CRITICAL" "[ $rc -eq 0 ]"
rmdir "$own_path_dir" 2>/dev/null

# --- graceful degradation with a stripped-down PATH ---------------------------
# `mkdir` (and bash itself) are the one genuinely hard baseline dependency
# for Escal8 to run at all, now that it fails closed rather than silently
# limping along without a secure private workspace (see
# docs/LIMITATIONS.md). `chmod`/`stat`/`find`/`sudo`/`getcap`/`ss` are all
# deliberately left OUT here to prove every check that needs them degrades
# to an explicit SKIP instead of crashing or silently misreporting.
mintools_dir="$(mktemp -d)"
for b in bash cat grep sed awk sort uniq head tail tr wc date ps id hostname uname basename dirname mkdir; do
    p="$(command -v "$b" 2>/dev/null)"
    [ -n "$p" ] && ln -sf "$p" "$mintools_dir/$b"
done
out="$(PATH="$mintools_dir" "$SCRIPT" --no-color --profile full 2>&1)"
rc=$?
check "minimal-tool run does not crash (bash reports a real exit code)" "[ $rc -le 2 ]"
check "minimal-tool run reports SKIP for missing find-based checks" "printf '%s' \"\$out\" | grep -q 'SKIP.*find not available'"
check "minimal-tool run reports SKIP for missing sudo" "printf '%s' \"\$out\" | grep -q 'SKIP.*sudo not installed'"
check "minimal-tool run never shows a bash traceback/unbound var error" \
    "! printf '%s' \"\$out\" | grep -qE 'unbound variable|command not found: '"
check "minimal-tool run still produces a private temp workspace (no fail-closed exit 3)" "[ $rc -ne 3 ]"
rm -rf "$mintools_dir"

# --- fail-closed behavior when even mkdir is unavailable -----------------------
# This is the one case where Escal8 is now expected to refuse to run at
# all, loudly, rather than silently continuing without a safe workspace -
# this is the explicit fail-closed behavior this fix adds. With no mkdir
# AND no mktemp, there is no way to create a private directory at all.
bare_dir="$(mktemp -d)"
for b in bash cat grep; do
    p="$(command -v "$b" 2>/dev/null)"
    [ -n "$p" ] && ln -sf "$p" "$bare_dir/$b"
done
PATH="$bare_dir" "$SCRIPT" --no-color >$TEST_BARE_OUT 2>$TEST_BARE_ERR
rc=$?
check "with no mkdir/mktemp at all, Escal8 fails closed with exit code 3" "[ $rc -eq 3 ]"
check "the fail-closed error explains why, on stderr" "grep -q 'secure private temp directory' $TEST_BARE_ERR"
check "fail-closed produces no partial/misleading findings output on stdout" "[ ! -s $TEST_BARE_OUT ]"
rm -rf "$bare_dir" $TEST_BARE_OUT $TEST_BARE_ERR

# --- deleted-open file /proc fallback ----------------------------------------
# Use a fake proc tree: only symlink metadata is inspected, never target bytes.
delproc_dir="$(mktemp -d)"
mkdir -p "$delproc_dir/4242/fd"
printf 'fixture-process\n' > "$delproc_dir/4242/comm"
ln -s '/tmp/fixture.log (deleted)' "$delproc_dir/4242/fd/7"
delproc_out="$delproc_dir/output"
ESCAL8_PROC_ROOT="$delproc_dir" PATH="/usr/bin:/bin" "$SCRIPT" --no-color --checks deleted_files >"$delproc_out" 2>&1
check "deleted-open /proc fallback detects deleted symlink target metadata" \
    "grep -q 'Processes hold deleted files open' '$delproc_out' && grep -q 'fixture-process' '$delproc_out'"
rm -rf "$delproc_dir"

# --- ACL parser regression cases (effective rights, numeric IDs) -------------
source "$ROOT_DIR/src/27_check_acl.sh"
acl_masked=$'user:1001:rwx #effective:r-x\ngroup:1002:r--'
_escal8_acl_has_effective_write "$acl_masked" 1001 " 1001 1002 " 1002
rc=$?
check "ACL parser ignores write removed by ACL mask" "[ $rc -ne 0 ]"
acl_group=$'group:1002:rwx #effective:rwx'
_escal8_acl_has_effective_write "$acl_group" 1001 " 1001 1002 " 1002
rc=$?
check "ACL parser detects effective write through matching numeric group" "[ $rc -eq 0 ]"
acl_readonly=$'user:1001:r--\ngroup:1002:r--'
_escal8_acl_has_effective_write "$acl_readonly" 1001 " 1001 1002 " 1002
rc=$?
check "ACL parser does not treat read-only entries as writable" "[ $rc -ne 0 ]"

echo
echo "== Results: $((TESTS_RUN - TESTS_FAILED))/$TESTS_RUN passed =="
[ "$TESTS_FAILED" -eq 0 ]
