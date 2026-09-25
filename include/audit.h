/*
 * audit.h — 公共数据结构与报告 API
 * iot-firmware-audit (ifa)
 *
 * 该头文件定义一次固件根文件系统审计的核心数据结构：
 * 发现项(Finding) 与 审计报告(AuditReport)。
 * 所有扫描规则模块都通过 report_add() 向报告追加发现项。
 */
#ifndef IFA_AUDIT_H
#define IFA_AUDIT_H

#include <stddef.h>

#define IFA_MAX_FINDINGS 2048   /* 单次审计最多记录的发现项数量 */
#define IFA_PATH_LEN     512    /* 文件路径缓冲长度 */
#define IFA_STR_LEN      512    /* 描述文本缓冲长度 */

/* 发现项严重等级，数值越大越严重 */
typedef enum {
    SEV_INFO = 0,
    SEV_LOW,
    SEV_MEDIUM,
    SEV_HIGH,
    SEV_CRITICAL
} Severity;

/* 单条安全发现 */
typedef struct {
    char     rule_id[32];                 /* 规则编号，如 IFA-ACC-001 */
    Severity severity;                    /* 严重等级 */
    char     category[32];               /* 类别：account/secrets/suid/boot */
    char     file_path[IFA_PATH_LEN];    /* 相对 rootfs 的文件路径 */
    long     line;                       /* 行号(无则为0) */
    char     description[IFA_STR_LEN];  /* 人类可读描述 */
    char     detail[256];                /* 证据细节(命中的内容/用户名等) */
} Finding;

/* 一次完整审计的结果容器 */
typedef struct {
    Finding items[IFA_MAX_FINDINGS];
    int     count;
    int     files_scanned;              /* 已扫描的普通文件数 */
    char    root_dir[IFA_PATH_LEN];     /* 被审计的根目录 */
} AuditReport;

/* 初始化报告：绑定 root 目录、清零计数 */
void report_init(AuditReport *rep, const char *root_dir);

/* 追加一条发现；报告满时返回 -1，成功返回 0 */
int  report_add(AuditReport *rep, const Finding *f);

/* 把枚举等级转成大写字符串，用于文本/JSON 输出 */
const char *severity_str(Severity s);

/* 统计某等级及以上的发现数量（供摘要使用） */
int  report_count_at_least(const AuditReport *rep, Severity s);

#endif /* IFA_AUDIT_H */
