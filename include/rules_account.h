/*
 * rules_account.h — 账号口令规则
 * 审计 /etc/passwd 与 /etc/shadow 中的弱口令、空口令、明文哈希。
 */
#ifndef IFA_RULES_ACCOUNT_H
#define IFA_RULES_ACCOUNT_H

#include "audit.h"

/* 扫描 <root>/etc/shadow 文件，把弱口令发现写入 rep。返回写入条数。 */
int audit_shadow_file(AuditReport *rep, const char *shadow_path);

/* 扫描 <root>/etc/passwd 文件，发现"口令哈希直接存放在 passwd"的问题。 */
int audit_passwd_file(AuditReport *rep, const char *passwd_path);

/* ---- 以下为纯函数，便于单元测试，不依赖文件系统 ---- */

/*
 * 判断一行 shadow 记录是否存在弱/空口令。
 * 命中时填充 out 并返回 1；正常锁定/无登录账号返回 0。
 * shadow 行格式: 用户名:哈希:最后修改:最小:最大:警告:不活动:过期:保留
 */
int shadow_line_weak(const char *line, Finding *out);

/*
 * 判断一行 passwd 记录是否把哈希直接放在了第二字段(应为 'x')。
 * 命中时填充 out 并返回 1，否则返回 0。
 */
int passwd_line_stores_hash(const char *line, Finding *out);

#endif /* IFA_RULES_ACCOUNT_H */
