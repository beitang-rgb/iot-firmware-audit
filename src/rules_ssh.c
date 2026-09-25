/*
 * rules_ssh.c — /etc/ssh/sshd_config 弱配置检测
 */
#include "rules_ssh.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>

/* 去除行首空白，跳过注释与空行；返回第一个非空白字符 */
static const char *skip_ws_comment(const char *line)
{
    while (*line == ' ' || *line == '\t') line++;
    if (*line == '#' || *line == '\0') return NULL;
    return line;
}

int ssh_config_line_weak(const char *line, Finding *out)
{
    const char *p = skip_ws_comment(line);
    if (!p) return 0;

    /* 大小写不敏感匹配关键字 */
    char kw[64];
    size_t i = 0;
    while (p[i] && !isspace((unsigned char)p[i]) && i < sizeof(kw) - 1) {
        kw[i] = (char)tolower((unsigned char)p[i]);
        i++;
    }
    kw[i] = '\0';

    const char *val = p + i;
    while (*val == ' ' || *val == '\t') val++;

    struct { const char *key; const char *bad; const char *label; } WEAK[] = {
        { "permitrootlogin",  "yes",            "允许 root 直接 SSH 登录(PermitRootLogin yes)" },
        { "permitemptypasswords", "yes",        "允许空密码 SSH 登录" },
        { "passwordauthentication", "yes",      "启用明文密码认证(易被爆破)" },
        { "protocol",         "1",              "使用过时的 SSH Protocol 1" },
    };
    int n = (int)(sizeof(WEAK) / sizeof(WEAK[0]));
    for (int k = 0; k < n; k++) {
        if (strcmp(kw, WEAK[k].key) == 0) {
            char vbuf[32];
            size_t v = 0;
            while (val[v] && !isspace((unsigned char)val[v]) && v < sizeof(vbuf) - 1) {
                vbuf[v] = (char)tolower((unsigned char)val[v]);
                v++;
            }
            vbuf[v] = '\0';
            if (strcmp(vbuf, WEAK[k].bad) == 0) {
                memset(out, 0, sizeof(*out));
                snprintf(out->rule_id, sizeof(out->rule_id), "IFA-SSH-001");
                out->severity = SEV_MEDIUM;
                snprintf(out->category, sizeof(out->category), "ssh");
                snprintf(out->description, sizeof(out->description), "%s", WEAK[k].label);
                snprintf(out->detail, sizeof(out->detail), "%s %s", kw, vbuf);
                return 1;
            }
        }
    }
    return 0;
}

static int scan_ssh_file(AuditReport *rep, const char *full, const char *rel)
{
    FILE *fp = fopen(full, "r");
    if (!fp) return 0;
    char line[2048];
    long lineno = 0;
    int n = 0;
    while (fgets(line, sizeof(line), fp)) {
        lineno++;
        Finding f;
        if (ssh_config_line_weak(line, &f)) {
            snprintf(f.file_path, sizeof(f.file_path), "%s", rel);
            f.line = lineno;
            if (report_add(rep, &f) == 0) n++;
        }
    }
    fclose(fp);
    rep->files_scanned++;
    return n;
}

int audit_ssh_config(AuditReport *rep, const char *root)
{
    if (!rep || !root) return 0;
    /* 常见固件路径：/etc/ssh/sshd_config, /etc/sshd_config */
    static const char *cands[] = {
        "etc/ssh/sshd_config",
        "etc/sshd_config",
    };
    int n = 0;
    for (size_t i = 0; i < sizeof(cands) / sizeof(cands[0]); i++) {
        char full[1024];
        snprintf(full, sizeof(full), "%s/%s", root, cands[i]);
        struct stat st;
        if (stat(full, &st) == 0 && S_ISREG(st.st_mode))
            n += scan_ssh_file(rep, full, cands[i]);
    }
    return n;
}
