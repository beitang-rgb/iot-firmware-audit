/*
 * scanner.c — 扫描编排：初始化报告 → 跑注册表中全部规则 → 渲染输出
 */
#include "scanner.h"
#include "registry.h"
#include "report.h"
#include "report_html.h"
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

static int path_is_under(const char *rel, const char *prefix)
{
    const char *r = rel;
    const char *p = prefix;
    while (*p) {
        const char *pslash = strchr(p, '/');
        size_t plen = pslash ? (size_t)(pslash - p) : strlen(p);
        const char *rslash = strchr(r, '/');
        size_t rlen = rslash ? (size_t)(rslash - r) : strlen(r);
        if (plen != rlen || strncmp(p, r, plen) != 0) return 0;
        if (!pslash) break;
        if (!rslash) return 0;
        p = pslash + 1;
        r = rslash + 1;
    }
    return 1;
}

static void filter_exclude(AuditReport *rep, const char **exclude_dirs, int exclude_count)
{
    if (!exclude_dirs || exclude_count <= 0) return;
    int w = 0;
    for (int i = 0; i < rep->count; i++) {
        int excluded = 0;
        for (int j = 0; j < exclude_count; j++) {
            if (path_is_under(rep->items[i].file_path, exclude_dirs[j])) {
                excluded = 1;
                break;
            }
        }
        if (!excluded) {
            if (w != i) rep->items[w] = rep->items[i];
            w++;
        }
    }
    rep->count = w;
}

static int sev_in_whitelist(const char *only_sev, const char *sev_name)
{
    const char *p = only_sev;
    while (*p) {
        while (*p == ',' || *p == ' ') p++;
        if (!*p) break;
        const char *comma = strchr(p, ',');
        size_t len = comma ? (size_t)(comma - p) : strlen(p);
        while (len > 0 && p[len-1] == ' ') len--;
        if (len == strlen(sev_name) && strncmp(p, sev_name, len) == 0) return 1;
        if (!comma) break;
        p = comma + 1;
    }
    return 0;
}

static void filter_only_sev(AuditReport *rep, const char *only_sev)
{
    if (!only_sev || !*only_sev) return;
    int w = 0;
    for (int i = 0; i < rep->count; i++) {
        const char *sev = severity_str(rep->items[i].severity);
        if (sev_in_whitelist(only_sev, sev)) {
            if (w != i) rep->items[w] = rep->items[i];
            w++;
        }
    }
    rep->count = w;
}

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
    registry_run_all(&rep, opts->root_dir);
    filter_exclude(&rep, opts->exclude_dirs, opts->exclude_count);
    filter_only_sev(&rep, opts->only_sev);
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
    if (opts->output_html) {
        if (report_write_html(&rep, opts->output_html) == 0) {
            fprintf(stderr, "HTML 报告已写入: %s\n", opts->output_html);
        } else {
            fprintf(stderr, "scanner: 写 HTML 报告失败: %s\n", opts->output_html);
        }
    }
    return 0;
}
