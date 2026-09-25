/*
 * rules_components.c — 识别固件里的关键组件版本并匹配已知 CVE
 *
 * 对标 EMBA 的核心功能：BusyBox/OpenSSL 等组件版本过旧 → 直接关联 CVE。
 * 实现：fread 二进制前 256KB，找 "BusyBox vX.XX.Y" 之类的版本字符串，
 * 与硬编码的已知漏洞版本表比对。不追求全，只抓 IoT 最常被爆的几个。
 */
#include "rules_components.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>

/* 已知 CVE 条目：版本前缀 + CVE 编号 + 说明 */
struct CveEntry {
    const char *component;     /* busybox / openssl */
    int major, minor;          /* 版本 <= major.minor 即受影响 */
    const char *cve;
    const char *desc;
    int severity;              /* 1=MEDIUM 2=HIGH */
};

static const struct CveEntry CVE_DB[] = {
    /* BusyBox 著名漏洞 */
    { "busybox", 1, 20, "CVE-2011-2716", "HTTPd 目录遍历，可读任意文件", 2 },
    { "busybox", 1, 22, "CVE-2015-9261", "udhcpc 栈溢出", 2 },
    { "busybox", 1, 27, "CVE-2016-2147", "HTTPd 整数溢出导致 DoS", 1 },
    { "busybox", 1, 29, "CVE-2018-1000500", "udhcpc 信息泄露", 1 },
    { "busybox", 1, 30, "CVE-2021-28363", "wget 未校验证书中间人", 1 },
    /* OpenSSL */
    { "openssl", 1, 0, "CVE-2014-0160", "Heartbleed 心跳血漏，可读取内存私钥", 2 },
    { "openssl", 1, 1, "CVE-2016-0800", "DROWN 攻击，SSLv2 降级", 1 },
    { "openssl", 1, 1, "CVE-2022-0778", "BN_mod_sqrt 空指针崩溃", 1 },
};
#define N_CVE (int)(sizeof(CVE_DB)/sizeof(CVE_DB[0]))

/*
 * 纯函数：从一段内存里找 BusyBox 版本号，写到 out_major/out_minor。
 * 找到返回 1。
 */
int parse_busybox_version(const char *buf, long buf_len, int *out_major, int *out_minor)
{
    const char *needle = "BusyBox v";
    for (long i = 0; i + 10 < buf_len; i++) {
        if (memcmp(buf + i, needle, 9) == 0) {
            int major, minor;
            if (sscanf(buf + i + 9, "%d.%d", &major, &minor) >= 2) {
                *out_major = major;
                *out_minor = minor;
                return 1;
            }
        }
    }
    return 0;
}

/* 读一个文件前 max_read 字节到 buf */
static long slurp(const char *path, char *buf, long buf_sz)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    long n = fread(buf, 1, buf_sz, fp);
    fclose(fp);
    return n;
}

/* 比对版本：组件名 + (major.minor)，命中 CVE 表则报 */
static int check_version(AuditReport *rep, const char *component,
                         int major, int minor, const char *path)
{
    int n = 0;
    for (int i = 0; i < N_CVE; i++) {
        if (strcmp(CVE_DB[i].component, component) != 0) continue;
        if (major < CVE_DB[i].major ||
            (major == CVE_DB[i].major && minor <= CVE_DB[i].minor)) {
            Finding f;
            memset(&f, 0, sizeof(f));
            snprintf(f.rule_id, sizeof(f.rule_id), "IFA-COMP-001");
            f.severity = CVE_DB[i].severity == 2 ? SEV_HIGH : SEV_MEDIUM;
            snprintf(f.category, sizeof(f.category), "components");
            snprintf(f.file_path, sizeof(f.file_path), "%s", path);
            snprintf(f.description, sizeof(f.description),
                     "%s 版本 %d.%d 存在已知漏洞 %s",
                     component, major, minor, CVE_DB[i].cve);
            snprintf(f.detail, sizeof(f.detail), "%s", CVE_DB[i].desc);
            if (report_add(rep, &f) == 0) n++;
        }
    }
    return n;
}

int audit_components(AuditReport *rep, const char *root)
{
    char buf[262144];   /* 256KB */
    char path[1024];
    int n = 0;

    /* BusyBox 可能在 /bin/busybox 或 /usr/bin/busybox */
    const char *candidates[] = { "bin/busybox", "usr/bin/busybox", NULL };
    for (int i = 0; candidates[i]; i++) {
        snprintf(path, sizeof(path), "%s/%s", root, candidates[i]);
        long len = slurp(path, buf, sizeof(buf));
        if (len > 0) {
            int maj, min;
            if (parse_busybox_version(buf, len, &maj, &min)) {
                n += check_version(rep, "busybox", maj, min, candidates[i]);
                rep->files_scanned++;
                break;
            }
        }
    }

    /* OpenSSL：扫 libcrypto.so 的版本字符串 */
    snprintf(path, sizeof(path), "%s/usr/lib/libcrypto.so", root);
    long len = slurp(path, buf, sizeof(buf));
    if (len > 0) {
        rep->files_scanned++;
        /* OpenSSL x.x.x 特征："OpenSSL 1.0.2" 之类 */
        for (long i = 0; i + 12 < len; i++) {
            if (memcmp(buf + i, "OpenSSL ", 8) == 0) {
                int maj, min;
                if (sscanf(buf + i + 8, "%d.%d", &maj, &min) >= 2) {
                    n += check_version(rep, "openssl", maj, min, "usr/lib/libcrypto.so");
                    break;
                }
            }
        }
    }
    return n;
}
