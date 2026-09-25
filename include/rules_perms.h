/*
 * rules_perms.h — 敏感文件权限检测
 */
#ifndef IFA_RULES_PERMS_H
#define IFA_RULES_PERMS_H
#include "audit.h"

/* 检查 /etc/shadow 不应被 group/other 读取(应为 600 或 640)，
 * /etc/passwd 不应全局可写(应为 644)。 */
int audit_sensitive_perms(AuditReport *rep, const char *root);

#endif
