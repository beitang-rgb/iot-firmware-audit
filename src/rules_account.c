/*
 * rules_account.c — /etc/passwd 与 /etc/shadow 弱口令审计
 *
 * 设计要点：真正"判断一行是否有问题"的逻辑全部下沉到纯函数
 * shadow_line_weak() / passwd_line_stores_hash()，不触碰文件系统，
 * 因此可以被单元测试直接覆盖。文件遍历只负责取行、调用纯函数、回填路径。
 */
#include "rules_account.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* 去掉行尾换行 */
static void chomp(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) {
        s[n - 1] = '\0';
        n--;
    }
}

/* 逐字段冒号切分，保留空字段(strtok_r 会把连续冒号合并，导致空口令识别错)。
 * 把 buf 原地按 : 切开，field_ptrs[i] 指向第 i 个字段，返回字段数。
 */
static int split_colon_fields(char *buf, char *field_ptrs[], int max_fields)
{
    int n = 0;
    char *p = buf;
    field_ptrs[n++] = p;
    for (; *p && n < max_fields; p++) {
        if (*p == ':') {
            *p = '\0';
            field_ptrs[n++] = p + 1;
        }
    }
    return n;
}

/*
 * 纯函数：判断 shadow 一行是否弱/空口令。
 * 字段约定: user:hash:lastchange:min:max:warn:inactive:expire
 */
int shadow_line_weak(const char *line, Finding *out)
{
    char buf[1024];
    snprintf(buf, sizeof(buf), "%s", line);

    /* 注释行或空行不算问题 */
    if (buf[0] == '#' || buf[0] == '\0') return 0;

    char *fields[16];
    int nf = split_colon_fields(buf, fields, 16);
    if (nf < 2) return 0;            /* 至少要有 user:hash 两列 */
    char *user = fields[0];
    char *hash = fields[1];          /* 空字符串""才代表空口令 */

    memset(out, 0, sizeof(*out));
    snprintf(out->rule_id, sizeof(out->rule_id), "IFA-ACC-001");
    snprintf(out->category, sizeof(out->category), "account");

    /* 情况1：空口令字段 —— 直接回车即可登录，最高危 */
    if (hash[0] == '\0') {
        out->severity = SEV_CRITICAL;
        snprintf(out->description, sizeof(out->description),
                 "账号 '%s' 存在空口令(shadow 第二字段为空)", user);
        snprintf(out->detail, sizeof(out->detail), "user=%s empty password", user);
        return 1;
    }

    /* 情况2：被锁定/禁止登录的账号 (* 或 ! 开头) 不算弱口令 */
    if (hash[0] == '*' || hash[0] == '!') {
        return 0;
    }

    /* 情况3：MD5 哈希($1$) 算法过弱，已被 GPU 暴力破解 */
    if (strncmp(hash, "$1$", 3) == 0) {
        out->severity = SEV_MEDIUM;
        snprintf(out->description, sizeof(out->description),
                 "账号 '%s' 使用已过时的 MD5($1$) 口令哈希", user);
        snprintf(out->detail, sizeof(out->detail), "user=%s hash=MD5-crypt", user);
        return 1;
    }

    /* 情况4：既不是标准 $id$ 盐值哈希，也不是锁定标记 —— 疑似明文/弱格式 */
    if (hash[0] != '$') {
        out->severity = SEV_HIGH;
        snprintf(out->description, sizeof(out->description),
                 "账号 '%s' 的口令字段不是标准加盐哈希(疑似明文)", user);
        snprintf(out->detail, sizeof(out->detail), "user=%s field_len=%zu",
                 user, strlen(hash));
        return 1;
    }

    /* 其余($5$ SHA256 / $6$ SHA512)视为可接受 */
    return 0;
}

/*
 * 纯函数：判断 passwd 一行是否把哈希放在了第二字段。
 */
int passwd_line_stores_hash(const char *line, Finding *out)
{
    char buf[1024];
    snprintf(buf, sizeof(buf), "%s", line);
    if (buf[0] == '#' || buf[0] == '\0') return 0;

    char *save = NULL;
    char *user = strtok_r(buf, ":", &save);
    char *field = strtok_r(NULL, ":", &save);
    if (!user || !field) return 0;

    /* 'x' 表示真正哈希在 shadow 中；'*'/'!' 表示禁止登录 —— 都正常 */
    if (strcmp(field, "x") == 0 || field[0] == '*' || field[0] == '!' ||
        field[0] == '\0') {
        return 0;
    }

    memset(out, 0, sizeof(*out));
    snprintf(out->rule_id, sizeof(out->rule_id), "IFA-ACC-002");
    out->severity = SEV_MEDIUM;
    snprintf(out->category, sizeof(out->category), "account");
    snprintf(out->description, sizeof(out->description),
             "账号 '%s' 的口令哈希直接存放在 /etc/passwd(应为 'x')", user);
    snprintf(out->detail, sizeof(out->detail), "user=%s passwd_field=%s",
             user, field);
    return 1;
}

/* 逐行扫描一个文件，调用传入的纯判定函数 */
static int scan_lines(const char *path, const char *rel_path,
                      int (*judge)(const char *, Finding *), AuditReport *rep)
{
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;   /* 文件不存在不算失败(很多 rootfs 没有 shadow) */

    char line[2048];
    int  n = 0;
    long lineno = 0;
    while (fgets(line, sizeof(line), fp)) {
        lineno++;
        chomp(line);
        Finding f;
        if (judge(line, &f)) {
            snprintf(f.file_path, sizeof(f.file_path), "%s", rel_path);
            f.line = lineno;
            if (report_add(rep, &f) == 0) n++;
        }
    }
    fclose(fp);
    return n;
}

int audit_shadow_file(AuditReport *rep, const char *shadow_path)
{
    return scan_lines(shadow_path, "etc/shadow", shadow_line_weak, rep);
}

int audit_passwd_file(AuditReport *rep, const char *passwd_path)
{
    return scan_lines(passwd_path, "etc/passwd", passwd_line_stores_hash, rep);
}
