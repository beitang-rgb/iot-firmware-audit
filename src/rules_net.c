/*
 * rules_net.c — 启动脚本里的无认证对外服务
 */
#include "rules_net.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/stat.h>

/* 可疑对外服务特征 */
static const struct { const char *needle; const char *label; } NET_PATS[] = {
    { "telnetd", "telnetd 监听(默认常无口令)" },
    { "ftpd",    "ftp 服务(明文传输凭据)" },
    { "nc -l",   "netcat 监听端口" },
    { "busybox httpd", "裸 httpd 无认证" },
};
#define N_NET (sizeof(NET_PATS)/sizeof(NET_PATS[0]))

static int scan_net_file(AuditReport *rep, const char *full, const char *rel)
{
    FILE *fp = fopen(full, "r");
    if (!fp) return 0;
    char line[2048];
    long lineno = 0;
    int n = 0;
    while (fgets(line, sizeof(line), fp)) {
        lineno++;
        char lower[2048];
        size_t i;
        for (i = 0; line[i] && i < sizeof(lower)-1; i++)
            lower[i] = (char)tolower((unsigned char)line[i]);
        lower[i] = '\0';
        for (size_t p = 0; p < N_NET; p++) {
            if (strstr(lower, NET_PATS[p].needle)) {
                Finding f;
                memset(&f, 0, sizeof(f));
                snprintf(f.rule_id, sizeof(f.rule_id), "IFA-NET-001");
                f.severity = SEV_MEDIUM;
                snprintf(f.category, sizeof(f.category), "network");
                snprintf(f.file_path, sizeof(f.file_path), "%s", rel);
                f.line = lineno;
                snprintf(f.description, sizeof(f.description),
                         "启动脚本暴露无认证/弱认证对外服务");
                snprintf(f.detail, sizeof(f.detail), "%s", NET_PATS[p].label);
                if (report_add(rep, &f) == 0) n++;
                break;
            }
        }
    }
    fclose(fp);
    rep->files_scanned++;
    return n;
}

int audit_listening_services(AuditReport *rep, const char *root)
{
    if (!rep || !root) return 0;
    char dir[1024];
    snprintf(dir, sizeof(dir), "%s/etc/init.d", root);
    DIR *d = opendir(dir);
    if (!d) return 0;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        char full[1024], rel[1024];
        snprintf(full, sizeof(full), "%s/%s", dir, e->d_name);
        snprintf(rel, sizeof(rel), "etc/init.d/%s", e->d_name);
        struct stat st;
        if (stat(full, &st) == 0 && S_ISREG(st.st_mode))
            n += scan_net_file(rep, full, rel);
    }
    closedir(d);
    return n;
}
