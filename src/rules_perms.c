/*
 * rules_perms.c — 敏感文件权限检测
 */
#include "rules_perms.h"
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

int audit_sensitive_perms(AuditReport *rep, const char *root)
{
    if (!rep || !root) return 0;
    int n = 0;

    /* shadow：不应被 group/other 读(即权限中不能有 0040/0004 之外的读) */
    char path[1024];
    snprintf(path, sizeof(path), "%s/etc/shadow", root);
    struct stat st;
    if (stat(path, &st) == 0) {
        int mode = st.st_mode & 0777;
        /* 合法: 600 (rw-------) 或 640 (rw-r-----) */
        int ok = (mode == 0600 || mode == 0640);
        if (!ok) {
            Finding f;
            memset(&f, 0, sizeof(f));
            snprintf(f.rule_id, sizeof(f.rule_id), "IFA-PERM-002");
            f.severity = SEV_HIGH;
            snprintf(f.category, sizeof(f.category), "filesystem");
            snprintf(f.file_path, sizeof(f.file_path), "%s", "etc/shadow");
            snprintf(f.description, sizeof(f.description),
                     "/etc/shadow 权限过宽，口令哈希可能被普通用户读取");
            snprintf(f.detail, sizeof(f.detail), "mode=0%o (期望 0600/0640)", mode);
            if (report_add(rep, &f) == 0) n++;
        }
        rep->files_scanned++;
    }

    /* passwd：不应全局可写 */
    snprintf(path, sizeof(path), "%s/etc/passwd", root);
    if (stat(path, &st) == 0) {
        int mode = st.st_mode & 0777;
        if (mode & 0002) {
            Finding f;
            memset(&f, 0, sizeof(f));
            snprintf(f.rule_id, sizeof(f.rule_id), "IFA-PERM-003");
            f.severity = SEV_MEDIUM;
            snprintf(f.category, sizeof(f.category), "filesystem");
            snprintf(f.file_path, sizeof(f.file_path), "%s", "etc/passwd");
            snprintf(f.description, sizeof(f.description),
                     "/etc/passwd 全局可写，任意用户可篡改账号");
            snprintf(f.detail, sizeof(f.detail), "mode=0%o", mode);
            if (report_add(rep, &f) == 0) n++;
        }
        rep->files_scanned++;
    }
    return n;
}
