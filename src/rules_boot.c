/*
 * rules_boot.c — 可疑启动项/后门服务检测
 *
 * 在 /etc/init.d/、/etc/rcS、/etc/rc.local、/etc/inittab 中查找
 * 无认证 telnetd、netcat 监听、反向 shell 等典型后门自启动特征。
 * 判定下沉到纯函数 line_is_suspicious_boot()。
 */
#include "rules_boot.h"
#include <dirent.h>
#include <sys/stat.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <stdio.h>

/* 可疑启动特征表 */
static const struct {
    const char *needle;
    const char *label;
    int         high;   /* 1=高危, 0=中危 */
} BOOT_PATTERNS[] = {
    { "telnetd",            "启动了 telnetd(固件常默认无口令登录)", 1 },
    { "busybox telnetd",    "busybox telnetd(无认证调试端口)",       1 },
    { "/dev/tcp/",          "bash 反向 shell 特征(/dev/tcp/)",       1 },
    { "nc -l",              "netcat 监听端口",                       1 },
    { "netcat",             "调用 netcat",                           0 },
    { "tftpd",              "启动 tftp 服务(易被用于烧写/窃取)",     0 },
};
#define N_BOOT (sizeof(BOOT_PATTERNS)/sizeof(BOOT_PATTERNS[0]))

int line_is_suspicious_boot(const char *line, char *out_detail, size_t out_size)
{
    char lower[2048];
    size_t i = 0;
    for (; line[i] && i < sizeof(lower) - 1; i++) {
        lower[i] = (char)tolower((unsigned char)line[i]);
    }
    lower[i] = '\0';

    for (size_t p = 0; p < N_BOOT; p++) {
        if (strstr(lower, BOOT_PATTERNS[p].needle)) {
            if (out_detail && out_size) {
                snprintf(out_detail, out_size, "%s [high=%d]",
                         BOOT_PATTERNS[p].label, BOOT_PATTERNS[p].high);
            }
            return 1;
        }
    }
    return 0;
}

/* 扫描单个启动脚本 */
static int scan_boot_file(AuditReport *rep, const char *full, const char *rel)
{
    FILE *fp = fopen(full, "r");
    if (!fp) return 0;

    char line[2048];
    long lineno = 0;
    int  n = 0;
    while (fgets(line, sizeof(line), fp)) {
        lineno++;
        char detail[256];
        if (line_is_suspicious_boot(line, detail, sizeof(detail))) {
            Finding f;
            memset(&f, 0, sizeof(f));
            snprintf(f.rule_id, sizeof(f.rule_id), "IFA-BOOT-001");
            snprintf(f.category, sizeof(f.category), "boot");
            f.severity = (strstr(detail, "[high=1]")) ? SEV_HIGH : SEV_MEDIUM;
            snprintf(f.file_path, sizeof(f.file_path), "%s", rel);
            f.line = lineno;
            snprintf(f.description, sizeof(f.description),
                     "启动脚本中出现可疑服务/后门特征");
            /* 去掉标记后缀，只留可读说明 */
            char *p = strstr(detail, " [high=");
            if (p) *p = '\0';
            snprintf(f.detail, sizeof(f.detail), "%s", detail);
            if (report_add(rep, &f) == 0) n++;
        }
    }
    fclose(fp);
    return n;
}

/* 扫描 init.d 目录下的每个脚本 */
static int scan_boot_dir(AuditReport *rep, const char *root)
{
    char path[IFA_PATH_LEN];
    snprintf(path, sizeof(path), "%s/etc/init.d", root);

    DIR *d = opendir(path);
    if (!d) return 0;

    int n = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        char full[2048];
        char rel[2048];
        snprintf(full, sizeof(full), "%s/%s", path, ent->d_name);
        snprintf(rel, sizeof(rel), "etc/init.d/%s", ent->d_name);
        struct stat st;
        if (stat(full, &st) == 0 && S_ISREG(st.st_mode)) {
            n += scan_boot_file(rep, full, rel);
        }
    }
    closedir(d);
    return n;
}

int audit_boot_scripts(AuditReport *rep, const char *root)
{
    int n = 0;
    n += scan_boot_dir(rep, root);

    /* 常见的单文件启动入口，逐个尝试打开(不存在则跳过) */
    static const char *files[] = {
        "etc/rcS", "etc/rc.local", "etc/inittab",
    };
    for (size_t i = 0; i < sizeof(files)/sizeof(files[0]); i++) {
        char full[IFA_PATH_LEN];
        snprintf(full, sizeof(full), "%s/%s", root, files[i]);
        n += scan_boot_file(rep, full, files[i]);
    }
    return n;
}
