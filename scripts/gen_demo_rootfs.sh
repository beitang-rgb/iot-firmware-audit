#!/usr/bin/env bash
# scripts/gen_demo_rootfs.sh — 生成一个"故意有漏洞"的演示 rootfs
set -euo pipefail

ROOT="${1:-examples/demo_rootfs}"
rm -rf "$ROOT"
mkdir -p "$ROOT/etc/init.d" "$ROOT/etc/ssh" "$ROOT/www/cgi-bin" "$ROOT/usr/bin" "$ROOT/var"

cat > "$ROOT/etc/passwd" <<'EOF'
root:x:0:0:root:/root:/bin/sh
admin:$1$salt$hash:0:0:admin:/home/admin:/bin/sh
EOF

ADMIN_HASH="$(openssl passwd -1 -salt s4ltV4lue admin)"
cat > "$ROOT/etc/shadow" <<EOF
admin::18000:0:99999:7:::
support:$ADMIN_HASH:18000:0:99999:7:::
EOF

cat > "$ROOT/etc/config" <<'EOF'
wifi_password=hunter2
psk=deadbeef
EOF

cat > "$ROOT/etc/init.d/S50telnet" <<'EOF'
#!/bin/sh
/usr/sbin/telnetd -l /bin/sh
EOF

cat > "$ROOT/etc/ssh/sshd_config" <<'EOF'
Port 22
PermitRootLogin yes
PasswordAuthentication yes
EOF

echo "backup" > "$ROOT/www/config.backup.tar.gz"

cat > "$ROOT/www/cgi-bin/exec.cgi" <<'EOF'
#!/bin/sh
echo "Content-Type: text/html"
EOF

chmod 0644 "$ROOT/etc/shadow"
chmod 0644 "$ROOT/etc/ssh/sshd_config"
chmod 0755 "$ROOT/etc/init.d/S50telnet"
chmod 0777 "$ROOT/www/cgi-bin/exec.cgi"

mkdir -p "$ROOT/usr/bin"
echo '#!/bin/sh' > "$ROOT/usr/bin/debug"
chmod 4755 "$ROOT/usr/bin/debug"

echo "log" > "$ROOT/var/motd"
chmod 0666 "$ROOT/var/motd"

mkdir -p "$ROOT/bin"
printf '\x7fELF\x02\x01\x01\x00BusyBox v1.19.4 (2024-01-01 built)\n' > "$ROOT/bin/busybox"
chmod 0755 "$ROOT/bin/busybox"

echo "demo rootfs generated at: $ROOT"
