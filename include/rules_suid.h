/*
 * rules_suid.h — SUID/SGID 危险权限规则
 * 递归遍历 rootfs，标记设置了 SUID/SGID 位的可执行文件。
 */
#ifndef IFA_RULES_SUID_H
#define IFA_RULES_SUID_H

#include "audit.h"
#include <sys/types.h>

/* 递归遍历 root 目录，记录所有 SUID/SGID 文件。返回写入条数。 */
int audit_suid_tree(AuditReport *rep, const char *root);

/* 纯函数：判断 st_mode 是否包含 SUID 或 SGID 位。 */
int mode_is_suid_sgid(mode_t m);

#endif /* IFA_RULES_SUID_H */
