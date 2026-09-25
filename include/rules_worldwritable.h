/*
 * rules_worldwritable.h — 全局可写文件检测
 */
#ifndef IFA_RULES_WORLDWRITABLE_H
#define IFA_RULES_WORLDWRITABLE_H
#include "audit.h"

/* 递归扫描 root，找出对所有人可写的文件(排除 /tmp)。 */
int audit_worldwritable(AuditReport *rep, const char *root);

#endif
