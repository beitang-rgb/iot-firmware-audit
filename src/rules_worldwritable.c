/*
 * rules_worldwritable.c — 全局可写文件
 */
#include "rules_worldwritable.h"
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

#define MAX_WALK_DEPTH 32

/* 判断 rel 路径是否落在某个名为 tmp 的目录里（精确匹配路径段，
 * 避免 strstr 把 /usr/local/backup/tmp_old/ 整个误跳过） */
static int path_is_under_tmp(const char *rel)
{
    /* rel 形如 "etc" 或 "etc/init.d"；从开头逐段比较 */
    const char *p = rel;
    while (*p) {
        const char *slash = strchr(p, '/');
        size_t seg_len = slash ? (size_t)(slash - p) : strlen(p);
        if (seg_len == 3 && strncmp(p, "tmp", 3) == 0) return 1;
        if (!slash) break;
        p = slash + 1;
    }
    return 0;
}

static int walk(AuditReport *rep, const char *root, const char *rel, int depth)
{
    if (depth > MAX_WALK_DEPTH) return 0;
    char full[2048];
    snprintf(full, sizeof(full), "%s/%s", root, rel[0] ? rel : ".");
    DIR *d = opendir(full);
    if (!d) return 0;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        /* 不再跳过隐藏文件：.ssh/authorized_keys、.config 里的 o+w 文件也要报 */
        char child[2048];
        snprintf(child, sizeof(child), "%s/%s", rel, e->d_name);
        char fullpath[2048];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", root, child);
        struct stat st;
        if (lstat(fullpath, &st) != 0) continue;
        if (S_ISLNK(st.st_mode)) continue;
        if (S_ISDIR(st.st_mode)) {
            if (path_is_under_tmp(child)) continue;   /* 只跳真 tmp 目录 */
            n += walk(rep, root, child, depth + 1);
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
    return walk(rep, root, "", 0);
}
