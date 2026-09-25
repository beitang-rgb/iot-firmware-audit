#!/usr/bin/env bash
# tests/test_integration.sh — 端到端集成测试
set -euo pipefail

cd "$(dirname "$0")/.."

echo "=== building ifa ==="
gcc -Wall -Wextra -g -Wno-format-truncation -Iinclude src/audit.c src/report.c src/report_html.c \
    src/rules_account.c src/rules_secrets.c src/rules_suid.c src/rules_boot.c \
    src/rules_net.c src/rules_worldwritable.c src/rules_ssh.c src/rules_perms.c \
    src/rules_web.c src/rules_crack.c src/rules_components.c src/remediation.c \
    src/registry.c src/extract.c src/scanner.c src/cli.c \
    -o ifa -lcrypt

WORKDIR="$(mktemp -d)"
bash scripts/gen_demo_rootfs.sh "$WORKDIR/rootfs"

echo "=== running audit against demo_rootfs ==="
./ifa "$WORKDIR/rootfs" --json /tmp/ifa_integration.json >/dev/null

echo "=== asserting findings ==="
grep -q '"severity": "CRITICAL"' /tmp/ifa_integration.json \
    || { echo "FAIL: no CRITICAL finding"; exit 1; }
grep -q 'IFA-ACC-001' /tmp/ifa_integration.json || { echo "FAIL: IFA-ACC-001 missing"; exit 1; }
grep -q 'IFA-ACC-002' /tmp/ifa_integration.json || { echo "FAIL: IFA-ACC-002 missing"; exit 1; }
grep -q 'IFA-SEC-001' /tmp/ifa_integration.json || { echo "FAIL: IFA-SEC-001 missing"; exit 1; }
grep -q 'IFA-NET-001' /tmp/ifa_integration.json || { echo "FAIL: IFA-NET-001 missing"; exit 1; }
grep -q 'IFA-SSH-001' /tmp/ifa_integration.json || { echo "FAIL: IFA-SSH-001 missing"; exit 1; }
grep -q 'IFA-WEB-001' /tmp/ifa_integration.json || { echo "FAIL: IFA-WEB-001 missing"; exit 1; }
grep -q 'IFA-WEB-002' /tmp/ifa_integration.json || { echo "FAIL: IFA-WEB-002 missing"; exit 1; }
grep -q 'IFA-PERM-001' /tmp/ifa_integration.json || { echo "FAIL: IFA-PERM-001 missing"; exit 1; }
grep -q 'IFA-PERM-002' /tmp/ifa_integration.json || { echo "FAIL: IFA-PERM-002 missing"; exit 1; }
grep -q 'IFA-FS-001' /tmp/ifa_integration.json || { echo "FAIL: IFA-FS-001 missing"; exit 1; }
grep -q 'IFA-BOOT-001' /tmp/ifa_integration.json || { echo "FAIL: IFA-BOOT-001 missing"; exit 1; }
grep -q 'IFA-CRACK-001' /tmp/ifa_integration.json || { echo "FAIL: IFA-CRACK-001 missing"; exit 1; }
grep -q 'remediation' /tmp/ifa_integration.json || { echo "FAIL: remediation field missing"; exit 1; }
grep -q 'IFA-COMP-001' /tmp/ifa_integration.json || { echo "FAIL: IFA-COMP-001 missing"; exit 1; }

echo "ALL INTEGRATION TESTS PASSED"
