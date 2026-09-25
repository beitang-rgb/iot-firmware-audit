/*
 * scanner.c — 扫描编排：初始化报告 → 跑注册表中全部规则 → 渲染输出
 *
 * 注意：具体跑哪些规则在 src/registry.c 的规则表里维护，
 * 这里不再硬编码调用任何 audit_* 函数。
 */
#include "scanner.h"
#include "registry.h"
#include "report.h"
#include "report_html.h"
#include <stdio.h>
#include <sys/stat.h>

int scanner_run(const CliOptions *opts)
{
    if (!opts || !opts->root_dir) {
        fprintf(stderr, "scanner: missing root_dir\n");
        return -1;
    }

    struct stat st;
    if (stat(opts->root_dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "scanner: rootfs not a directory: %s\n", opts->root_dir);
        return -1;
    }

    AuditReport rep;
    report_init(&rep, opts->root_dir);

    /* 跑注册表里的所有规则（新增规则无需改这里） */
    registry_run_all(&rep, opts->root_dir);

    /* 文本/JSON 输出 */
    if (opts->output_file) {
        FILE *fp = fopen(opts->output_file, "w");
        if (fp) {
            report_render(&rep, opts->format, fp);
            fclose(fp);
        } else {
            fprintf(stderr, "scanner: cannot open output %s, falling back to stdout\n",
                    opts->output_file);
            report_render(&rep, opts->format, stdout);
        }
    } else {
        report_render(&rep, opts->format, stdout);
    }

    /* HTML 报告 */
    if (opts->output_html) {
        if (report_write_html(&rep, opts->output_html) == 0) {
            fprintf(stderr, "HTML 报告已写入: %s\n", opts->output_html);
        } else {
            fprintf(stderr, "scanner: 写 HTML 报告失败: %s\n", opts->output_html);
        }
    }
    return 0;
}
