/*
 * scanner.h — 扫描编排器
 * 负责把各条规则按 rootfs 路径调度起来，生成最终报告。
 */
#ifndef IFA_SCANNER_H
#define IFA_SCANNER_H

#include "audit.h"

typedef struct {
    const char *root_dir;
    const char *format;
    const char *output_file;
    const char *output_html;
    const char **exclude_dirs;
    int         exclude_count;
    const char  *only_sev;
} CliOptions;

int scanner_run(const CliOptions *opts);

#endif
