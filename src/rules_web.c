/*
 * rules_web.c — Web 暴露面规则实现
 */
#include "rules_web.h"
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

/* 判断文件名是否像"配置备份"——放在 web 根下等于公开密码 */
static int looks_like_backup(const char *name)
{
    size_t n = strlen(name);
    if (n >= 4 && strcmp(name + n - 4, ".bak") == 0) return 1;
    if (strstr(name, "backup") != NULL) return 1;
    if (n >= 7 && strcmp(name + n - 7, ".tar.gz") == 0) return 1;
    if (strstr(name, "config") != NULL && strstr(name, ".conf") != NULL) return 1;
    return 0;
}

static int scan_web_dir(AuditReport *rep, const char *web_dir, const char *rel)
{
    DIR *d = opendir(web_dir);
    if (!d) return 0;

    int n = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;

        char full[512];
        char rpath[512];
        snprintf(full, sizeof(full), "%s/%s", web_dir, ent->d_name);
        snprintf(rpath, sizeof(rpath), "%s/%s", rel, ent->d_name);

        struct stat st;
        if (lstat(full, &st) != 0) continue;
        if (S_ISLNK(st.st_mode)) continue;   /* 不跟随软链 */

        if (S_ISDIR(st.st_mode)) {
            /* cgi-bin 目录单独看里面脚本是否全局可写 */
            if (strcmp(ent->d_name, "cgi-bin") == 0) {
                DIR *cg = opendir(full);
                if (cg) {
                    struct dirent *ce;
                    while ((ce = readdir(cg)) != NULL) {
                        if (strcmp(ce->d_name, ".") == 0 ||
                            strcmp(ce->d_name, "..") == 0) continue;
                        char cfull[512], crpath[512];
                        snprintf(cfull, sizeof(cfull), "%s/%s", full, ce->d_name);
                        snprintf(crpath, sizeof(crpath), "%s/cgi-bin/%s", rel, ce->d_name);
                        struct stat cst;
                        if (lstat(cfull, &cst) != 0) continue;
                        if (S_ISLNK(cst.st_mode)) continue;
                        if (S_ISREG(cst.st_mode) && (cst.st_mode & S_IWOTH)) {
                            Finding f;
                            memset(&f, 0, sizeof(f));
                            snprintf(f.rule_id, sizeof(f.rule_id), "IFA-WEB-002");
                            f.severity = SEV_HIGH;
                            snprintf(f.category, sizeof(f.category), "web");
                            snprintf(f.file_path, sizeof(f.file_path), "%s", crpath);
                            snprintf(f.description, sizeof(f.description),
                                     "cgi-bin 脚本全局可写，攻击者可替换为后门");
                            snprintf(f.detail, sizeof(f.detail), "mode=0%o",
                                     (unsigned int)(cst.st_mode & 07777));
                            if (report_add(rep, &f) == 0) n++;
                        }
                    }
                    closedir(cg);
                }
            }
            /* 不再递归进其他 web 子目录（保持快速） */
        } else if (S_ISREG(st.st_mode)) {
            if (looks_like_backup(ent->d_name)) {
                Finding f;
                memset(&f, 0, sizeof(f));
                snprintf(f.rule_id, sizeof(f.rule_id), "IFA-WEB-001");
                f.severity = SEV_HIGH;
                snprintf(f.category, sizeof(f.category), "web");
                snprintf(f.file_path, sizeof(f.file_path), "%s", rpath);
                snprintf(f.description, sizeof(f.description),
                         "疑似配置备份文件暴露在 web 根目录，可能被直接下载");
                snprintf(f.detail, sizeof(f.detail), "file=%s", ent->d_name);
                if (report_add(rep, &f) == 0) n++;
            }
        }
    }
    closedir(d);
    return n;
}

int audit_web_exposures(AuditReport *rep, const char *root)
{
    char web[512];
    snprintf(web, sizeof(web), "%s/www", root);
    return scan_web_dir(rep, web, "www");
}
