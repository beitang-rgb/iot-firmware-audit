/*
 * rules_worldwritable.c — 全局可写文件
 */
#include "rules_worldwritable.h"
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

#define IFA_PATH_LEN 512

static int walk(AuditReport *rep, const char *root, const char *rel)
{
    char full[1024];
    snprintf(full, sizeof(full), "%s/%s", root, rel[0] ? rel : ".");
    DIR *d = opendir(full);
    if (!d) return 0;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        char child[1024];
        snprintf(child, sizeof(child), "%s/%s", rel, e->d_name);
        char fullpath[1024];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", root, child);
        struct stat st;
        if (lstat(fullpath, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            /* 跳过 tmp 等临时目录本身 */
            if (strstr(child, "/tmp") || strcmp(child, "tmp") == 0) continue;
            n += walk(rep, root, child);
        } else if (S_ISREG(st.st_mode)) {
            if (st.st_mode & 0002) {  /* o+w */
                Finding f;
                memset(&f, 0, sizeof(f));
                snprintf(f.rule_id, sizeof(f.rule_id), "IFA-FS-001");
                f.severity = SEV_LOW;
                snprintf(f.category, sizeof(f.category), "filesystem");
                snprintf(f.file_path, sizeof(f.file_path), "%s", child);
                snprintf(f.description, sizeof(f.description),
                         "文件对所有人可写(全局写权限)");
                snprintf(f.detail, sizeof(f.detail), "mode=0%o", st.st_mode & 0777);
                if (report_add(rep, &f) == 0) n++;
            }
        }
    }
    closedir(d);
    return n;
}

int audit_worldwritable(AuditReport *rep, const char *root)
{
    if (!rep || !root) return 0;
    return walk(rep, root, "");
}
