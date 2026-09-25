/*
 * scanner.h — 扫描编排器
 * 负责把各条规则按 rootfs 路径调度起来，生成最终报告。
 */
#ifndef IFA_SCANNER_H
#define IFA_SCANNER_H

#include "audit.h"

/* 命令行选项（由 cli 模块填充） */
typedef struct {
    const char *root_dir;       /* 固件根目录(必选) */
    const char *format;         /* "text" 或 "json" */
    const char *output_file;    /* NULL 表示输出到 stdout */
    const char *output_html;    /* NULL 表示不输出 HTML */
    const char *output_sarif;   /* NULL 表示不输出 SARIF */
    const char **exclude_dirs;  /* 要排除的相对路径段数组，NULL 表示无 */
    int         exclude_count;  /* exclude_dirs 中的条目数 */
    const char  *only_sev;       /* 逗号分隔的严重度白名单，NULL 表示不过滤 */
} CliOptions;

/*
 * 执行完整审计：依次调用四类规则，然后渲染输出。
 * 成功返回 0，失败(如根目录不存在)返回 -1。
 */
int scanner_run(const CliOptions *opts);

#endif
