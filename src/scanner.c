/*
 * scanner.c — 扫描编排：把所有规则按 rootfs 路径调度起来
 */
#include "scanner.h"
#include "rules_account.h"
#include "rules_secrets.h"
#include "rules_suid.h"
#include "rules_boot.h"
#include "rules_net.h"
#include "rules_worldwritable.h"
#include "rules_ssh.h"
#include "rules_perms.h"
#include "report.h"
#include "report_html.h"
#include <stdio.h>
#include <string.h>
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

    char path[1024];

    /* 1) 账号口令：/etc/passwd 与 /etc/shadow */
    snprintf(path, sizeof(path), "%s/etc/shadow", opts->root_dir);
    audit_shadow_file(&rep, path);
    snprintf(path, sizeof(path), "%s/etc/passwd", opts->root_dir);
    audit_passwd_file(&rep, path);

    /* 2) 硬编码敏感串：递归扫描 /etc */
    snprintf(path, sizeof(path), "%s/etc", opts->root_dir);
    audit_secrets_in_dir(&rep, path);

    /* 3) SUID/SGID：整树递归 */
    audit_suid_tree(&rep, opts->root_dir);

    /* 4) 可疑启动项 */
    audit_boot_scripts(&rep, opts->root_dir);

    /* 5) v0.2: 对外服务 + 全局可写 */
    audit_listening_services(&rep, opts->root_dir);
    audit_worldwritable(&rep, opts->root_dir);

    /* 6) v0.3: SSH 弱配置 + 敏感文件权限 */
    audit_ssh_config(&rep, opts->root_dir);
    audit_sensitive_perms(&rep, opts->root_dir);

    /* 7) 文本/JSON 输出 */
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

    /* 8) v0.2: HTML 报告 */
    if (opts->output_html) {
        if (report_write_html(&rep, opts->output_html) == 0) {
            fprintf(stderr, "HTML 报告已写入: %s\n", opts->output_html);
        } else {
            fprintf(stderr, "scanner: 写 HTML 报告失败: %s\n", opts->output_html);
        }
    }
    return 0;
}
