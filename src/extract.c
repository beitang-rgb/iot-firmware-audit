/*
 * extract.c — 调用 binwalk 解包固件并定位 rootfs
 */
#include "extract.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>

static int is_rootfs_dirname(const char *name)
{
    return strcmp(name, "squashfs-root") == 0 ||
           strcmp(name, "jffs2-root") == 0 ||
           strcmp(name, "ubifs-root") == 0 ||
           strcmp(name, "cpio-root") == 0;
}

static int has_passwd(const char *dir)
{
    char p[1024];
    snprintf(p, sizeof(p), "%s/etc/passwd", dir);
    struct stat st;
    return stat(p, &st) == 0 && S_ISREG(st.st_mode);
}

static int has_shadow(const char *dir)
{
    char p[1024];
    snprintf(p, sizeof(p), "%s/etc/shadow", dir);
    struct stat st;
    return stat(p, &st) == 0 && S_ISREG(st.st_mode);
}

#define MAX_CAND 16

static void collect_rootfs(const char *dir, char cands[][1024], int *ncand, int depth)
{
    if (depth > 6) return;
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        char full[1024];
        snprintf(full, sizeof(full), "%s/%s", dir, e->d_name);
        struct stat st;
        if (lstat(full, &st) != 0) continue;
        if (!S_ISDIR(st.st_mode)) continue;
        if (is_rootfs_dirname(e->d_name)) {
            if (*ncand < MAX_CAND) {
                snprintf(cands[*ncand], 1024, "%s", full);
                (*ncand)++;
            }
            continue;
        }
        if (has_passwd(full)) {
            if (*ncand < MAX_CAND) {
                snprintf(cands[*ncand], 1024, "%s", full);
                (*ncand)++;
            }
            continue;
        }
        collect_rootfs(full, cands, ncand, depth + 1);
    }
    closedir(d);
}

static int find_rootfs(const char *dir, char *out, size_t out_sz, int depth)
{
    char cands[MAX_CAND][1024];
    int ncand = 0;
    collect_rootfs(dir, cands, &ncand, depth);
    if (ncand == 0) return 0;
    int best = 0;
    for (int i = 0; i < ncand; i++) {
        if (has_shadow(cands[i])) { best = i; break; }
    }
    snprintf(out, out_sz, "%s", cands[best]);
    return 1;
}

static void rmtree(const char *path)
{
    char cmd[1280];
    snprintf(cmd, sizeof(cmd), "rm -rf -- '%s'", path);
    system(cmd);
}

int extract_firmware(const char *firmware_path, char *out_dir, size_t out_sz)
{
    if (!firmware_path || !out_dir || out_sz == 0) return -1;
    char tmpl[] = "/tmp/ifa_extract_XXXXXX";
    if (!mkdtemp(tmpl)) {
        fprintf(stderr, "extract: mkdtemp failed\n");
        return -1;
    }
    int rc = -1;
    pid_t pid = fork();
    if (pid == 0) {
        char *argv[] = {
            "binwalk", "-Me", "-C", tmpl,
            (char *)firmware_path, NULL
        };
        execvp("binwalk", argv);
        _exit(127);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            if (find_rootfs(tmpl, out_dir, out_sz, 0)) {
                rc = 0;
            } else {
                fprintf(stderr, "extract: 解包后未找到 rootfs 目录\n");
            }
        } else {
            fprintf(stderr, "extract: binwalk 解包失败\n");
        }
    } else {
        perror("fork");
    }
    if (rc != 0) rmtree(tmpl);
    return rc;
}
