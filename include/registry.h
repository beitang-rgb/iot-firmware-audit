/*
 * registry.h — 规则注册表（函数指针表）
 *
 * 设计：每条规则是一个统一签名的函数 int run(AuditReport*, const char *root)，
 * 登记在一张静态表里。scanner 只需遍历这张表依次调用。
 * 新增一条规则 = 写一个 wrapper + 在表里加一行，scanner 一行都不用改。
 * 这就是 C 里最基础的"插件架构"。
 */
#ifndef IFA_REGISTRY_H
#define IFA_REGISTRY_H

#include "audit.h"

/* 规则统一入口：给报告 rep 和 rootfs 根目录 root，返回发现条数 */
typedef int (*RuleFunc)(AuditReport *rep, const char *root);

/* 表项：名字 + 函数指针 */
typedef struct {
    const char *name;
    RuleFunc    run;
} RuleEntry;

/* 跑注册表中全部规则，返回总发现数 */
int registry_run_all(AuditReport *rep, const char *root);

/* 打印已注册规则名（--list-rules 用） */
void registry_list(void);

#endif
