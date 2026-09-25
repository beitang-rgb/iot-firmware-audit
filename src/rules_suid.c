/*
 * rules_suid.c — 递归查找 SUID/SGID 可执行文件
 *
 * SUID 程序会以文件属主(常为 root)权限运行，是固件提权的常见入口。
 * 判定位掩码的逻辑放在纯函数 mode_is_suid_sgid() 以便单测。
 */
#include "rules_suid.h"
#include <dirent.h>
#include <sys/stat.h>
#include <string.h>
#include <stdio.h>

int mode_is_suid_sgid(mode_t m)
{
    return (m & S_ISUID) || (m & S_ISGID);
}

static int walk_suid(AuditReport *rep, const char *dir, const char *rel_base)
{
    DIR *d = opendir(dir);
    if (!d) return 0;

    int n = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;

        char full[IFA_PATH_LEN];
        char rel[IFA_PATH_LEN];
        snprintf(full, sizeof(full), "%s/%s", dir, ent->d_name);
        snprintf(rel, sizeof(rel), "%s/%s", rel_base, ent->d_name);

        struct stat st;
        if (lstat(full, &st) != 0) continue;   /* 用 lstat 不跟随软链 */

        if (S_ISDIR(st.st_mode)) {
            n += walk_suid(rep, full, rel);
        } else if (S_ISREG(st.st_mode) && mode_is_suid_sgid(st.st_mode)) {
            Finding f;
            memset(&f, 0, sizeof(f));
            snprintf(f.rule_id, sizeof(f.rule_id), "IFA-PERM-001");
            snprintf(f.category, sizeof(f.category), "suid");
            /* 属主为 root(uid 0) 的 SUID 提权风险更高 */
            f.severity = (st.st_uid == 0) ? SEV_HIGH : SEV_MEDIUM;
            snprintf(f.file_path, sizeof(f.file_path), "%s", rel);
            snprintf(f.description, sizeof(f.description),
                     "设置了 SUID/SGID 位的可执行文件，可能被用于本地提权");
            snprintf(f.detail, sizeof(f.detail),
                     "mode=0%o uid=%u gid=%u",
                     (unsigned int)(st.st_mode & 07777),
                     (unsigned int)st.st_uid, (unsigned int)st.st_gid);
            if (report_add(rep, &f) == 0) n++;
        }
    }
    closedir(d);
    return n;
}

int audit_suid_tree(AuditReport *rep, const char *root)
{
    return walk_suid(rep, root, "");
}
