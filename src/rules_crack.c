/*
 * rules_crack.c — 对 /etc/shadow 里的哈希跑内置弱口令字典
 *
 * 思路：EMBA 的核心卖点之一。固件里大量设备用出厂弱口令(admin/admin、root/123456)，
 * 我们不解大字典，只跑 20 个 IoT 设备最常见的出厂口令——命中即 CRITICAL。
 *
 * 纯函数 try_crack() 不碰文件，便于单测。
 */
#include "rules_crack.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <crypt.h>

/* IoT/路由器出厂最常见的弱口令小字典 */
static const char *WEAK_WORDS[] = {
    "", "admin", "password", "123456", "root", "toor", "guest",
    "user", "letmein", "qwerty", "iloveyou", "admin123",
    "password123", "123456789", "111111", "12345678",
    "123123", "root123", "support", "user123",
    "huawei", "zte", "sunrise", "telecomadmin",
};
#define N_WORDS (int)(sizeof(WEAK_WORDS)/sizeof(WEAK_WORDS[0]))

/*
 * 纯函数：给定一个完整 crypt 哈希(如 $1$salt$hash)，试字典。
 * 命中则把明文口令写 out_plain(至少 64 字节)并返回 1。
 * 失败返回 0。
 */
int try_crack(const char *full_hash, char *out_plain, size_t out_sz)
{
    if (!full_hash || full_hash[0] != '$') return 0;   /* 非标准哈希不试 */
    for (int i = 0; i < N_WORDS; i++) {
        const char *try = WEAK_WORDS[i];
        char *computed = crypt(try, full_hash);
        if (computed && strcmp(computed, full_hash) == 0) {
            snprintf(out_plain, out_sz, "%s", try);
            return 1;
        }
    }
    return 0;
}

/* 去掉行尾换行 */
static void chomp(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && (s[n-1] == '\n' || s[n-1] == '\r')) {
        s[n-1] = '\0';
        n--;
    }
}

int audit_crack_shadow(AuditReport *rep, const char *shadow_path)
{
    /* lstat 前置：防止固件里 etc/shadow -> /etc/shadow 读到宿主密码文件 */
    struct stat lst;
    if (lstat(shadow_path, &lst) != 0 || S_ISLNK(lst.st_mode) || !S_ISREG(lst.st_mode))
        return 0;

    FILE *fp = fopen(shadow_path, "r");
    if (!fp) return 0;

    char line[2048];
    int n = 0;
    while (fgets(line, sizeof(line), fp)) {
        chomp(line);
        if (line[0] == '#' || line[0] == '\0') continue;

        /* 切出 user 和 hash 两列（保留空字段） */
        char buf[2048];
        snprintf(buf, sizeof(buf), "%s", line);
        char *user = buf;
        char *hash = strchr(buf, ':');
        if (!hash) continue;
        *hash = '\0';
        hash++;
        char *end = strchr(hash, ':');
        if (end) *end = '\0';

        if (hash[0] != '$') continue;           /* 跳过空或锁定账号 */

        char plain[64];
        if (try_crack(hash, plain, sizeof(plain))) {
            Finding f;
            memset(&f, 0, sizeof(f));
            snprintf(f.rule_id, sizeof(f.rule_id), "IFA-CRACK-001");
            f.severity = SEV_CRITICAL;
            snprintf(f.category, sizeof(f.category), "account");
            snprintf(f.file_path, sizeof(f.file_path), "etc/shadow");
            snprintf(f.description, sizeof(f.description),
                     "账号 '%s' 的口令可被字典直接破解", user);
            /* 不写明文口令进报告，避免审计报告泄露被审计设备的凭据 */
            snprintf(f.detail, sizeof(f.detail),
                     "user=%s: 出厂弱口令字典命中，必须立即更换", user);
            if (report_add(rep, &f) == 0) n++;
        }
    }
    fclose(fp);
    rep->files_scanned++;
    return n;
}
