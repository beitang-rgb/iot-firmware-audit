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
#include "report_sarif.h"
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

/*
 * 判断 finding 的相对路径 rel 是否落在 exclude 前缀目录 prefix 下。
 * 逐段比较（与 rules_worldwritable.c 的 path_is_under_tmp 同思路），
 * 避免 strstr 把 /usr/local/backup/tmp_old/ 误判为 tmp。
 *   rel    如 "etc/shadow"、"tmp/foo/bar"
 *   prefix 如 "tmp"、"var/log"
 */
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

        if (!pslash) break;          /* prefix 的最后一段已匹配 */
        if (!rslash) return 0;       /* rel 比 prefix 短，不可能是其子目录 */
        p = pslash + 1;
        r = rslash + 1;
    }
    return 1;
}

/* 从报告中移除 file_path 落在任意 exclude 目录下的 finding（数组前移 + count--） */
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

/* 判断严重度名称是否在逗号分隔白名单中（不修改原字符串） */
static int sev_in_whitelist(const char *only_sev, const char *sev_name)
{
    const char *p = only_sev;
    while (*p) {
        while (*p == ',' || *p == ' ') p++;   /* 跳过分隔符和前导空格 */
        if (!*p) break;
        const char *comma = strchr(p, ',');
        size_t len = comma ? (size_t)(comma - p) : strlen(p);
        while (len > 0 && p[len - 1] == ' ') len--;   /* 去掉尾部空格 */
        if (len == strlen(sev_name) && strncmp(p, sev_name, len) == 0) return 1;
        if (!comma) break;
        p = comma + 1;
    }
    return 0;
}

/* 从报告中移除严重度不在白名单中的 finding */
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

    /* 跑注册表里的所有规则（新增规则无需改这里） */
    registry_run_all(&rep, opts->root_dir);

    /* 后过滤：先按排除目录过滤，再按严重度白名单过滤（均不改结构定义，数组前移 + count--） */
    filter_exclude(&rep, opts->exclude_dirs, opts->exclude_count);
    filter_only_sev(&rep, opts->only_sev);

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

    /* SARIF 报告（GitHub Code Scanning 兼容） */
    if (opts->output_sarif) {
        if (report_write_sarif(&rep, opts->output_sarif) == 0) {
            fprintf(stderr, "SARIF 报告已写入: %s\n", opts->output_sarif);
        } else {
            fprintf(stderr, "scanner: 写 SARIF 报告失败: %s\n", opts->output_sarif);
        }
    }
    return 0;
}
