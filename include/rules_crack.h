/*
 * rules_crack.h — 弱口令字典破解
 */
#ifndef IFA_RULES_CRACK_H
#define IFA_RULES_CRACK_H
#include "audit.h"

/* 纯函数：试字典，命中返回 1 并写 out_plain */
int try_crack(const char *full_hash, char *out_plain, size_t out_sz);

/* 扫一个 shadow 文件 */
int audit_crack_shadow(AuditReport *rep, const char *shadow_path);

#endif
