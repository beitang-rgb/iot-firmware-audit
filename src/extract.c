/*
 * extract.c — 调用 binwalk 解包固件并定位 rootfs
 */
#include "extract.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>

/* 在 dir 下递归查找名为 "squashfs-root" 的目录，找到则把完整路径写入 out */
static int find_rootfs(const char *dir, char *out, size_t out_sz, int depth)
{
    if (depth > 6) return 0;
    DIR *d = opendir(dir);
    if (!d) return 0;
    struct dirent *e;
    int found = 0;
    while ((e = readdir(d))) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        char full[1024];
        snprintf(full, sizeof(full), "%s/%s", dir, e->d_name);
        struct stat st;
        if (lstat(full, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            if (strcmp(e->d_name, "squashfs-root") == 0) {
                snprintf(out, out_sz, "%s", full);
                found = 1;
                break;
            }
            if (find_rootfs(full, out, out_sz, depth + 1)) { found = 1; break; }
        }
    }
    closedir(d);
    return found;
}

int extract_firmware(const char *firmware_path, char *out_dir, size_t out_sz)
{
    if (!firmware_path || !out_dir || out_sz == 0) return -1;

    /* 检查 binwalk 是否可用 */
    if (system("which binwalk > /dev/null 2>&1") != 0) {
        fprintf(stderr, "extract: 未找到 binwalk，请先安装 (sudo apt install binwalk)\n");
        return -1;
    }

    /* 建一个临时工作目录 */
    char tmpdir[512];
    snprintf(tmpdir, sizeof(tmpdir), "/tmp/ifa_extract_%d", (int)getpid());
    mkdir(tmpdir, 0755);

    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
             "binwalk -Me -C %s \"%s\" > /dev/null 2>&1", tmpdir, firmware_path);
    int rc = system(cmd);
    if (rc != 0) {
        fprintf(stderr, "extract: binwalk 解包失败\n");
        return -1;
    }

    if (!find_rootfs(tmpdir, out_dir, out_sz, 0)) {
        fprintf(stderr, "extract: 解包后未找到 squashfs-root 目录\n");
        return -1;
    }
    return 0;
}
