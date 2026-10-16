#!/usr/bin/env bash
# Disposable-environment integration test: runs Escal8 inside a chroot'd
# minimal rootfs against deliberately vulnerable and hardened fixtures,
# as both root and an unprivileged user, and checks the findings/exit
# codes match expectations. Requires root (for chroot) - run via sudo if
# needed. Rebuilds the fixture from scratch each run via
# build_chroot_fixture.sh, so it never depends on a stale checked-in state.
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOTFS="$ROOT_DIR/tests/fixtures/chroot_rootfs"
FAILED=0

if [ "$(id -u)" -ne 0 ]; then
    echo "run_chroot_tests.sh requires root (for chroot). Try: sudo $0" >&2
    exit 1
fi

echo "== Building fixture rootfs =="
set +e
bash "$ROOT_DIR/tests/fixtures/build_chroot_fixture.sh"
fixture_rc=$?
set -e
if [ "$fixture_rc" -eq 77 ]; then
    echo "SKIP: chroot integration suite unavailable in this environment."
    exit 77
elif [ "$fixture_rc" -ne 0 ]; then
    echo "ERROR: fixture setup failed (exit $fixture_rc)." >&2
    exit "$fixture_rc"
fi

echo "== Building escal8.sh =="
"$ROOT_DIR/build.sh" >/dev/null
cp "$ROOT_DIR/dist/escal8.sh" "$ROOTFS/root/escal8.sh"

run_in_chroot() {
    local userspec="$1"; shift
    chroot --userspec="$userspec" "$ROOTFS" /bin/bash -c \
        'export PATH=/bin:/usr/bin:/usr/sbin:/sbin; export HOME=/tmp; cd /tmp; '"$*"
}

check() {
    local desc="$1" cond="$2"
    if eval "$cond"; then
        printf '  [PASS] %s\n' "$desc"
    else
        printf '  [FAIL] %s\n' "$desc"
        FAILED=$((FAILED+1))
    fi
}

echo "== Vulnerable fixture, as unprivileged user (uid 65534) =="
out="$(run_in_chroot 65534:65534 'bash /root/escal8.sh --no-color --checks users,cron,writable,nfs,suid --quiet')"
rc=$?
check "exit code is 2 (CRITICAL present)" "[ $rc -eq 2 ]"
check "duplicate UID 0 account flagged" "printf '%s' \"\$out\" | grep -q 'Non-root account(s) with UID 0'"
check "writable /etc/shadow flagged" "printf '%s' \"\$out\" | grep -q 'shadow is writable'"
check "writable /etc/crontab flagged" "printf '%s' \"\$out\" | grep -q '/etc/crontab is writable'"
check "world-writable cron.d script flagged" "printf '%s' \"\$out\" | grep -q 'World-writable file(s) in /etc/cron.d'"
check "no_root_squash NFS export flagged" "printf '%s' \"\$out\" | grep -q 'no_root_squash'"
check "unusually-located risky SUID binary flagged" "printf '%s' \"\$out\" | grep -q \"known privesc-capable program: /opt/vuln/find\""

echo "== Hardening the fixture in place =="
sed -i '/^backdoor:/d' "$ROOTFS/etc/passwd"
chown root:root "$ROOTFS/etc/shadow" "$ROOTFS/etc/crontab" "$ROOTFS/etc/cron.d/vulnjob"
chmod 640 "$ROOTFS/etc/shadow"
chmod 644 "$ROOTFS/etc/crontab" "$ROOTFS/etc/cron.d/vulnjob"
rm -f "$ROOTFS/opt/vuln/find" "$ROOTFS/etc/exports"

echo "== Hardened fixture, as unprivileged user (uid 65534) =="
out="$(run_in_chroot 65534:65534 'bash /root/escal8.sh --no-color --checks users,cron,writable,nfs,suid --quiet')"
rc=$?
check "exit code is 0 (no CRITICAL/HIGH)" "[ $rc -eq 0 ]"
check "no CRITICAL findings reported" "printf '%s' \"\$out\" | grep -q 'CRITICAL : 0'"
check "uid0 check reports OK, not just silence" "printf '%s' \"\$out\" | grep -qv 'SKIP.*uid0'" # sanity: not skipped elsewhere

echo "== Hardened fixture, as root (root-aware permission false-positive check) =="
# This is the fix #2 regression test in situ: root's DAC bypass must not
# turn a correctly-permissioned hardened system into false CRITICALs for
# path/users/writable - including /bin and /sbin, which are symlinks in
# this fixture's own rootfs just like on most real distros.
out="$(run_in_chroot 0:0 'bash /root/escal8.sh --no-color --checks path,users,writable --quiet')"
rc=$?
check "root run on hardened fixture: exit code is 0 (no false-positive CRITICAL/HIGH)" "[ $rc -eq 0 ]"
check "root run on hardened fixture: CRITICAL count is 0" "printf '%s' \"\$out\" | grep -q 'CRITICAL : 0'"

echo "== Vulnerable-again fixture, as root (misconfigurations must still be caught even as root) =="
chmod 666 "$ROOTFS/etc/shadow"
out="$(run_in_chroot 0:0 'bash /root/escal8.sh --no-color --checks users --quiet')"
check "root run still flags a genuinely misconfigured (666) shadow file" "printf '%s' \"\$out\" | grep -q 'shadow is readable by unprivileged users'"
chmod 640 "$ROOTFS/etc/shadow"

echo "== Minimal-tool run inside chroot (sudo/getcap/ss/systemctl absent by construction) =="
out="$(run_in_chroot 65534:65534 'bash /root/escal8.sh --no-color --profile full')"
check "SKIP reported for missing sudo, not a crash" "printf '%s' \"\$out\" | grep -q 'SKIP.*sudo not installed'"
check "SKIP reported for missing getcap, not a crash" "printf '%s' \"\$out\" | grep -q 'SKIP.*getcap not installed'"
check "SKIP reported for missing ss/netstat, not a crash" "printf '%s' \"\$out\" | grep -q 'SKIP.*ss, netstat'"
check "no bash 'command not found' noise leaks into output" "! printf '%s' \"\$out\" | grep -q 'command not found'"

echo
if [ "$FAILED" -eq 0 ]; then
    echo "All chroot integration checks passed."
else
    echo "$FAILED chroot integration check(s) FAILED."
fi
exit "$FAILED"
