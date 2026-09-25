/*
 * cli.c — 命令行入口与参数解析
 */
#include "scanner.h"
#include "extract.h"
#include "registry.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* IFA_VERSION 定义在 include/audit.h，与 JSON 报告共用，只改一处 */

static void usage(const char *prog)
{
    printf("iot-firmware-audit (ifa) v%s - IoT firmware rootfs security auditor\n\n", IFA_VERSION);
    printf("Usage: %s <rootfs_dir> [options]\n\n", prog);
    printf("  rootfs_dir     Extracted firmware root directory (e.g. squashfs-root/)\n");
    printf("  --extract BIN  Run binwalk on a raw .bin firmware, then audit\n");
    printf("  --json FILE    Write JSON report to FILE\n");
    printf("  --html FILE    Write standalone HTML report to FILE\n");
    printf("  --text         Human-readable report to stdout (default)\n");
    printf("  --exclude DIR  Exclude findings under relative path DIR (repeatable)\n");
    printf("  --only SEV     Keep only findings of given severities, e.g. CRITICAL,HIGH\n");
    printf("  -v, --version  Print version and exit\n");
    printf("  -h, --help     Show this help\n");
}

int main(int argc, char **argv)
{
    CliOptions opts;
    memset(&opts, 0, sizeof(opts));
    opts.format = "text";
    const char *extract_bin = NULL;
    char rootfs[1024];
    rootfs[0] = '\0';
    const char *exclude_arr[64];
    opts.exclude_dirs = exclude_arr;
    opts.exclude_count = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
            printf("ifa v%s (built %s %s)\n", IFA_VERSION, __DATE__, __TIME__);
            return 0;
        } else if (strcmp(argv[i], "--list-rules") == 0) {
            registry_list();
            return 0;
        } else if (strcmp(argv[i], "--json") == 0) {
            if (i + 1 >= argc || argv[i+1][0] == '-') {
                fprintf(stderr, "error: --json 需要一个输出文件路径\n");
                return 1;
            }
            opts.format = "json";
            opts.output_file = argv[++i];
        } else if (strcmp(argv[i], "--html") == 0) {
            if (i + 1 >= argc || argv[i+1][0] == '-') {
                fprintf(stderr, "error: --html 需要一个输出文件路径\n");
                return 1;
            }
            opts.output_html = argv[++i];
        } else if (strcmp(argv[i], "--extract") == 0) {
            if (i + 1 >= argc || argv[i+1][0] == '-') {
                fprintf(stderr, "error: --extract 需要一个固件文件路径\n");
                return 1;
            }
            extract_bin = argv[++i];
        } else if (strcmp(argv[i], "--text") == 0) {
            opts.format = "text";
            opts.output_file = NULL;
        } else if (strcmp(argv[i], "--exclude") == 0) {
            if (i + 1 >= argc || argv[i+1][0] == '-') {
                fprintf(stderr, "error: --exclude 需要一个目录路径\n");
                return 1;
            }
            if (opts.exclude_count < 64) {
                exclude_arr[opts.exclude_count++] = argv[++i];
            } else {
                fprintf(stderr, "error: --exclude 最多 64 个\n");
                return 1;
            }
        } else if (strcmp(argv[i], "--only") == 0) {
            if (i + 1 >= argc || argv[i+1][0] == '-') {
                fprintf(stderr, "error: --only 需要一个严重度列表(如 CRITICAL,HIGH)\n");
                return 1;
            }
            opts.only_sev = argv[++i];
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "error: unknown option '%s'\n\n", argv[i]);
            usage(argv[0]);
            return 1;
        } else {
            opts.root_dir = argv[i];
        }
    }

    if (extract_bin) {
        printf("=== iot-firmware-audit v%s (extract mode) ===\n", IFA_VERSION);
        printf("firmware: %s\n\n", extract_bin);
        if (extract_firmware(extract_bin, rootfs, sizeof(rootfs)) != 0) {
            fprintf(stderr, "extract failed\n");
            return 1;
        }
        printf("extracted rootfs: %s\n\n", rootfs);
        opts.root_dir = rootfs;
    }

    if (!opts.root_dir) {
        fprintf(stderr, "error: missing rootfs directory\n\n");
        usage(argv[0]);
        return 1;
    }

    printf("=== iot-firmware-audit v%s ===\n", IFA_VERSION);
    printf("rootfs: %s\n\n", opts.root_dir);

    int rc = scanner_run(&opts);
    if (rc != 0) fprintf(stderr, "\naudit finished with errors\n");
    return rc;
}
