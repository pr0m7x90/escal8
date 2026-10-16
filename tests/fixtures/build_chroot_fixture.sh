#!/usr/bin/env bash
# Builds a disposable, minimal Linux rootfs under tests/fixtures/chroot_rootfs
# for chroot-based integration testing of Escal8. Requires root (for chroot
# and mknod) and a handful of host tools (ldd, chroot, mknod, cp).
#
# The fixture is NOT checked in pre-built (it contains binaries, shared
# libraries, and a device node that don't survive most packaging/transfer
# methods cleanly) - run this script to (re)create it locally, then run
# tests/run_chroot_tests.sh against it.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ROOTFS="$ROOT_DIR/tests/fixtures/chroot_rootfs"

if [ "$(id -u)" -ne 0 ]; then
    echo "This script requires root (for chroot/mknod). Try: sudo $0" >&2
    exit 1
fi

rm -rf "$ROOTFS"
mkdir -p "$ROOTFS"/bin "$ROOTFS"/usr/bin "$ROOTFS"/usr/sbin "$ROOTFS"/sbin \
         "$ROOTFS"/etc/cron.d "$ROOTFS"/proc "$ROOTFS"/dev "$ROOTFS"/tmp \
         "$ROOTFS"/root "$ROOTFS"/opt/vuln

copy_bin() {
    local b; b="$(command -v "$1" 2>/dev/null)" || return 0
    [ -z "$b" ] && return 0
    mkdir -p "$ROOTFS$(dirname "$b")"
    cp -n "$b" "$ROOTFS$b" 2>/dev/null || true
    local lib
    for lib in $(ldd "$b" 2>/dev/null | awk '{print $3}' | grep '^/'); do
        mkdir -p "$ROOTFS$(dirname "$lib")"
        cp -n "$lib" "$ROOTFS$lib" 2>/dev/null || true
    done
    for lib in $(ldd "$b" 2>/dev/null | awk '/ld-linux/{print $1}'); do
        mkdir -p "$ROOTFS$(dirname "$lib")"
        cp -n "$lib" "$ROOTFS$lib" 2>/dev/null || true
    done
}

# Minimal toolset: enough for Escal8's "full" profile to run meaningfully,
# while still exercising its SKIP paths for tools we deliberately omit
# (getcap, sudo, ss, netstat, systemctl, ip, curl, wget, python).
for tool in bash cat grep sed awk sort uniq head tail tr wc date ps id \
            hostname uname basename dirname ls find chmod mkdir env stat; do
    copy_bin "$tool"
done

for f in "$ROOTFS"/usr/bin/*; do
    [ -e "$f" ] || continue
    ln -sf "/usr/bin/$(basename "$f")" "$ROOTFS/bin/$(basename "$f")"
done

# Some sandbox/container environments run as UID 0 but deny CAP_MKNOD.
# Exit 77 (skip) rather than leave a broken rootfs that creates misleading
# downstream test failures. The runner treats this as an environment skip.
if ! mknod -m 666 "$ROOTFS/dev/null" c 1 3 2>/dev/null; then
    echo "SKIP: this environment cannot create /dev/null (CAP_MKNOD unavailable); chroot integration tests require a real device node." >&2
    exit 77
fi
chmod 1777 "$ROOTFS/tmp"

# --- Planted vulnerable fixtures --------------------------------------------
cat > "$ROOTFS/etc/passwd" <<'EOF'
root:x:0:0:root:/root:/bin/bash
backdoor:x:0:1000:backdoor:/home/backdoor:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
EOF

: > "$ROOTFS/etc/shadow"
chmod 666 "$ROOTFS/etc/shadow"

echo "# fixture crontab" > "$ROOTFS/etc/crontab"
chmod 666 "$ROOTFS/etc/crontab"

echo "#!/bin/bash" > "$ROOTFS/etc/cron.d/vulnjob"
chmod 777 "$ROOTFS/etc/cron.d/vulnjob"

cat > "$ROOTFS/etc/exports" <<'EOF'
/srv/share *(rw,no_root_squash)
EOF

cp "$ROOTFS/usr/bin/find" "$ROOTFS/opt/vuln/find"
chmod 4777 "$ROOTFS/opt/vuln/find"

echo 'PRETTY_NAME="Escal8 Fixture Linux"' > "$ROOTFS/etc/os-release"

echo "Fixture rootfs built at: $ROOTFS"
echo "Try it:"
echo "  cp dist/escal8.sh '$ROOTFS/root/escal8.sh'"
echo "  chroot --userspec=65534:65534 '$ROOTFS' /bin/bash -c \\"
echo "    'export PATH=/bin:/usr/bin; export HOME=/tmp; cd /tmp; bash /root/escal8.sh --no-color'"
