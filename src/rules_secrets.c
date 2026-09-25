/*
 * rules_secrets.c — 在 /etc 下查找硬编码的密码/密钥/Token
 *
 * 判定逻辑下沉到纯函数 line_has_secret()：它对一行文本做大小写无关的
 * 模式匹配。文件遍历层只负责递归读取 etc 目录、逐行调用并回填路径。
 */
#include "rules_secrets.h"
#include <dirent.h>
#include <sys/stat.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <stdio.h>

/* 敏感串模式表(needle 为小写形式，匹配时对行做小写化) */
static const struct {
    const char *needle;
    const char *label;
} SECRET_PATTERNS[] = {
    { "begin rsa private key", "PEM RSA 私钥" },
    { "begin private key",     "PEM 私钥" },
    { "password=",             "硬编码 password" },
    { "passwd=",                "硬编码 passwd" },
    { "secret=",                "硬编码 secret" },
    { "token=",                 "硬编码 token" },
    { "api_key",                "硬编码 API Key" },
    { "apikey",                 "硬编码 API Key" },
    { "wpa_passphrase",         "WiFi 预共享密钥" },
    { "psk=",                   "预共享密钥(PSK)" },
};
#define N_PATTERNS (sizeof(SECRET_PATTERNS)/sizeof(SECRET_PATTERNS[0]))

/* 纯函数：判断一行是否命中敏感串 */
int line_has_secret(const char *line, char *out_detail, size_t out_size)
{
    char lower[2048];
    size_t i = 0;
    for (; line[i] && i < sizeof(lower) - 1; i++) {
        lower[i] = (char)tolower((unsigned char)line[i]);
    }
    lower[i] = '\0';

    for (size_t p = 0; p < N_PATTERNS; p++) {
        if (strstr(lower, SECRET_PATTERNS[p].needle)) {
            if (out_detail && out_size) {
                snprintf(out_detail, out_size, "命中: %s",
                         SECRET_PATTERNS[p].label);
            }
            return 1;
        }
    }
    return 0;
}

/* 对单个文本文件逐行检查 */
static int scan_secret_file(AuditReport *rep, const char *full,
                            const char *rel)
{
    FILE *fp = fopen(full, "r");
    if (!fp) return 0;

    char line[2048];
    long lineno = 0;
    int  n = 0;
    while (fgets(line, sizeof(line), fp)) {
        lineno++;
        char detail[128];
        if (line_has_secret(line, detail, sizeof(detail))) {
            Finding f;
            memset(&f, 0, sizeof(f));
            snprintf(f.rule_id, sizeof(f.rule_id), "IFA-SEC-001");
            snprintf(f.category, sizeof(f.category), "secrets");
            /* 私钥视为高危，其余硬编码串为中危 */
            f.severity = strstr(detail, "私钥") ? SEV_HIGH : SEV_MEDIUM;
            snprintf(f.file_path, sizeof(f.file_path), "%s", rel);
            f.line = lineno;
            snprintf(f.description, sizeof(f.description),
                     "配置文件中疑似硬编码敏感串");
            snprintf(f.detail, sizeof(f.detail), "%s", detail);
            if (report_add(rep, &f) == 0) n++;
        }
    }
    fclose(fp);
    return n;
}

/* 递归遍历目录，对每个普通文件调用 scan_secret_file
 * depth 防止恶意固件用几千层硬目录把栈打爆 */
#define MAX_WALK_DEPTH 32
static int walk_secrets(AuditReport *rep, const char *dir, const char *rel_base, int depth)
{
    if (depth > MAX_WALK_DEPTH) return 0;
    DIR *d = opendir(dir);
    if (!d) return 0;

    int n = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        /* 跳过 . .. 与隐藏的大文件/符号链接环 */
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;

        char full[IFA_PATH_LEN];
        char rel[IFA_PATH_LEN];
        snprintf(full, sizeof(full), "%s/%s", dir, ent->d_name);
        snprintf(rel, sizeof(rel), "%s/%s", rel_base, ent->d_name);

        struct stat st;
        /* 用 lstat 不跟随符号链接：防止恶意固件里的软链
         * (如 /etc/evil -> /etc/shadow) 把扫描引到宿主机真实文件。 */
        if (lstat(full, &st) != 0) continue;
        if (S_ISLNK(st.st_mode)) continue;   /* 符号链接一律不进 */

        if (S_ISDIR(st.st_mode)) {
            n += walk_secrets(rep, full, rel, depth + 1);
        } else if (S_ISREG(st.st_mode)) {
            rep->files_scanned++;
            n += scan_secret_file(rep, full, rel);
        }
    }
    closedir(d);
    return n;
}

int audit_secrets_in_dir(AuditReport *rep, const char *etc_dir)
{
    return walk_secrets(rep, etc_dir, "etc", 0);
}
