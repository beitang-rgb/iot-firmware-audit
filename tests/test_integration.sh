#!/usr/bin/env bash
# tests/test_integration.sh — 端到端集成测试
# 编译 ifa，对 examples/demo_rootfs 跑一遍，断言 JSON 里命中了关键规则。
set -euo pipefail

cd "$(dirname "$0")/.."

echo "=== building ifa ==="
gcc -Wall -Wextra -g -Wno-format-truncation -Iinclude src/audit.c src/report.c src/report_html.c \
    src/rules_account.c src/rules_secrets.c src/rules_suid.c src/rules_boot.c \
    src/rules_net.c src/rules_worldwritable.c src/rules_ssh.c src/rules_perms.c \
    src/rules_web.c \
    src/registry.c src/extract.c src/scanner.c src/cli.c \
    -o ifa

# 在真 Linux 文件系统上生成 demo rootfs（/mnt/d 等 drvfs 不支持 SUID/chmod 位）
WORKDIR="$(mktemp -d)"
bash scripts/gen_demo_rootfs.sh "$WORKDIR/rootfs"

echo "=== running audit against demo_rootfs ==="
./ifa "$WORKDIR/rootfs" --json /tmp/ifa_integration.json >/dev/null

echo "=== asserting findings ==="
# 空口令必须报 CRITICAL
grep -q '"severity": "CRITICAL"' /tmp/ifa_integration.json \
    || { echo "FAIL: no CRITICAL finding (expected empty password)"; exit 1; }
# 空口令规则
grep -q 'IFA-ACC-001' /tmp/ifa_integration.json || { echo "FAIL: IFA-ACC-001 missing"; exit 1; }
# MD5 弱哈希
grep -q 'IFA-ACC-002' /tmp/ifa_integration.json || { echo "FAIL: IFA-ACC-002 missing"; exit 1; }
# 硬编码密码
grep -q 'IFA-SEC-001' /tmp/ifa_integration.json || { echo "FAIL: IFA-SEC-001 missing"; exit 1; }
# telnetd 对外服务
grep -q 'IFA-NET-001' /tmp/ifa_integration.json || { echo "FAIL: IFA-NET-001 missing"; exit 1; }
# SSH 弱配置
grep -q 'IFA-SSH-001' /tmp/ifa_integration.json || { echo "FAIL: IFA-SSH-001 missing"; exit 1; }
# web 配置备份暴露
grep -q 'IFA-WEB-001' /tmp/ifa_integration.json || { echo "FAIL: IFA-WEB-001 missing"; exit 1; }
# cgi-bin 全局可写
grep -q 'IFA-WEB-002' /tmp/ifa_integration.json || { echo "FAIL: IFA-WEB-002 missing"; exit 1; }
# SUID root 文件
grep -q 'IFA-PERM-001' /tmp/ifa_integration.json || { echo "FAIL: IFA-PERM-001 missing"; exit 1; }
# shadow 权限过宽
grep -q 'IFA-PERM-002' /tmp/ifa_integration.json || { echo "FAIL: IFA-PERM-002 missing"; exit 1; }
# 全局可写文件
grep -q 'IFA-FS-001' /tmp/ifa_integration.json || { echo "FAIL: IFA-FS-001 missing"; exit 1; }
# 可疑启动项
grep -q 'IFA-BOOT-001' /tmp/ifa_integration.json || { echo "FAIL: IFA-BOOT-001 missing"; exit 1; }

echo "ALL INTEGRATION TESTS PASSED"
