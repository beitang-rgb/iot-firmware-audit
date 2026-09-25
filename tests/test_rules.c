/*
 * test_rules.c — 单元测试：直接测纯判定函数，不依赖文件系统
 * 不用 cmocka，手写 assert，零外部依赖
 */
#include "rules_account.h"
#include "rules_secrets.h"
#include "rules_suid.h"
#include "rules_boot.h"
#include "rules_ssh.h"
#include "audit.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

static int tests_run = 0;
#define CHECK(cond) do { tests_run++; assert(cond); } while(0)

static void test_account(void) {
    Finding f;
    /* 空口令行 "admin::18000..." → 应识别为 CRITICAL */
    CHECK(shadow_line_weak("admin::18000:0:99999:7:::", &f) == 1);
    CHECK(f.severity == SEV_CRITICAL);
    /* 锁定账号 * → 不命中 */
    CHECK(shadow_line_weak("daemon:*:18000:0:99999:7:::", &f) == 0);
    /* MD5 $1$ → 命中 MEDIUM */
    CHECK(shadow_line_weak("user:$1$salt$hash:18000:0:99999:7:::", &f) == 1);
    CHECK(f.severity == SEV_MEDIUM);
    /* SHA512 $6$ → 正常不命中 */
    CHECK(shadow_line_weak("root:$6$salt$realsecurehash:18000:0:99999:7:::", &f) == 0);
    /* passwd 第二字段是 x → 正常 */
    CHECK(passwd_line_stores_hash("root:x:0:0:root:/root:/bin/sh", &f) == 0);
    /* passwd 第二字段是哈希 → 命中 */
    CHECK(passwd_line_stores_hash("root:$1$abc:0:0:root:/root:/bin/sh", &f) == 1);
}

static void test_secrets(void) {
    char detail[128];
    CHECK(line_has_secret("config password=admin123", detail, sizeof(detail)) == 1);
    CHECK(line_has_secret("API_KEY=abcdef", detail, sizeof(detail)) == 1);
    CHECK(line_has_secret("BEGIN RSA PRIVATE KEY-----", detail, sizeof(detail)) == 1);
    CHECK(line_has_secret("normal config value=hello", detail, sizeof(detail)) == 0);
}

static void test_suid(void) {
    CHECK(mode_is_suid_sgid(04755) == 1);  /* rwsr-xr-x */
    CHECK(mode_is_suid_sgid(02755) == 1);  /* rwxr-sr-x */
    CHECK(mode_is_suid_sgid(0755) == 0);
}

static void test_boot(void) {
    char detail[256];
    CHECK(line_is_suspicious_boot("/usr/sbin/telnetd -l /bin/sh", detail, sizeof(detail)) == 1);
    CHECK(line_is_suspicious_boot("nc -l -p 4444 -e /bin/sh", detail, sizeof(detail)) == 1);
    CHECK(line_is_suspicious_boot("echo starting up", detail, sizeof(detail)) == 0);
}

static void test_ssh(void) {
    Finding f;
    CHECK(ssh_config_line_weak("PermitRootLogin yes", &f) == 1);
    CHECK(f.severity == SEV_MEDIUM);
    CHECK(ssh_config_line_weak("PermitEmptyPasswords yes", &f) == 1);
    CHECK(ssh_config_line_weak("PasswordAuthentication yes", &f) == 1);
    CHECK(ssh_config_line_weak("PermitRootLogin no", &f) == 0);
    CHECK(ssh_config_line_weak("# PermitRootLogin yes", &f) == 0);
    CHECK(ssh_config_line_weak("", &f) == 0);
}

int main(void) {
    test_account();
    test_secrets();
    test_suid();
    test_boot();
    test_ssh();
    printf("ALL %d TESTS PASSED\n", tests_run);
    return 0;
}
