/*
 * extract.h — 原始固件自动解包
 */
#ifndef IFA_EXTRACT_H
#define IFA_EXTRACT_H
#include <stddef.h>

/*
 * 用 binwalk -Me 把 firmware_path 解包到临时目录，
 * 然后在里面递归找 squashfs-root 并把其路径写入 out_dir。
 * 成功返回 0；binwalk 不存在 / 解包失败 / 找不到 rootfs 返回 -1。
 */
int extract_firmware(const char *firmware_path, char *out_dir, size_t out_sz);

#endif
