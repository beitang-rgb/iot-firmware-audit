#!/usr/bin/env bash
# scripts/gen_demo_rootfs.sh — 生成一个"故意有漏洞"的演示 rootfs
# 供集成测试和演示使用。用法: bash scripts/gen_demo_rootfs.sh [输出目录]
set -euo pipefail

ROOT="${1:-examples/demo_rootfs}"
rm -rf "$ROOT"
mkdir -p "$ROOT/etc/init.d" "$ROOT/etc/ssh" "$ROOT/www/cgi-bin" "$ROOT/usr/bin" "$ROOT/var"

# /etc/passwd: admin 把口令哈希直接放在第二字段(应为 x)
cat > "$ROOT/etc/passwd" <<'EOF'
root:x:0:0:root:/root:/bin/sh
admin:$1$salt$hash:0:0:admin:/home/admin:/bin/sh
EOF

# /etc/shadow: admin 空口令 + support 用真实 admin 口令哈希(会被字典破解)
ADMIN_HASH="$(openssl passwd -1 -salt s4ltV4lue admin)"
cat > "$ROOT/etc/shadow" <<EOF
admin::18000:0:99999:7:::
support:$ADMIN_HASH:18000:0:99999:7:::
EOF

# /etc/config: 硬编码 Wi-Fi 密码与 PSK
cat > "$ROOT/etc/config" <<'EOF'
wifi_password=hunter2
psk=deadbeef
EOF

# /etc/init.d/S50telnet: 裸 telnetd 后门(无认证参数)
cat > "$ROOT/etc/init.d/S50telnet" <<'EOF'
#!/bin/sh
/usr/sbin/telnetd -l /bin/sh
EOF

# /etc/ssh/sshd_config: 允许 root 登录 + 明文密码认证
cat > "$ROOT/etc/ssh/sshd_config" <<'EOF'
Port 22
PermitRootLogin yes
PasswordAuthentication yes
EOF

# /www/config.backup.tar.gz: 配置备份暴露在 web 根(可被直接下载)
echo "backup" > "$ROOT/www/config.backup.tar.gz"

# /www/cgi-bin/exec.cgi: 故意全局可写(0777)，可被替换成后门
cat > "$ROOT/www/cgi-bin/exec.cgi" <<'EOF'
#!/bin/sh
echo "Content-Type: text/html"
EOF

# 权限: shadow 应 600，这里故意设为 644(可被普通用户读)
chmod 0644 "$ROOT/etc/shadow"
chmod 0644 "$ROOT/etc/ssh/sshd_config"
chmod 0755 "$ROOT/etc/init.d/S50telnet"
chmod 0777 "$ROOT/www/cgi-bin/exec.cgi"

# SUID root 调试程序（故意留的提权后门）
mkdir -p "$ROOT/usr/bin"
echo '#!/bin/sh' > "$ROOT/usr/bin/debug"
chmod 4755 "$ROOT/usr/bin/debug"

# 一个全局可写的普通文件
echo "log" > "$ROOT/var/motd"
chmod 0666 "$ROOT/var/motd"

echo "demo rootfs generated at: $ROOT"
