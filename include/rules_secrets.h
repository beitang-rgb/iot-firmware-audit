/*
 * rules_secrets.h — 硬编码密钥/口令字符串规则
 * 在 /etc 目录下递归扫描配置文件中的 password=、token=、私钥等敏感串。
 */
#ifndef IFA_RULES_SECRETS_H
#define IFA_RULES_SECRETS_H

#include "audit.h"

/* 递归扫描 etc_dir 下的普通文本文件，发现硬编码敏感串。返回写入条数。 */
int audit_secrets_in_dir(AuditReport *rep, const char *etc_dir);

/*
 * 纯函数：判断一行文本是否命中敏感串模式。
 * 命中时把命中的模式标签写入 out_detail(最多 out_size 字节)，返回 1；否则 0。
 */
int line_has_secret(const char *line, char *out_detail, size_t out_size);

#endif /* IFA_RULES_SECRETS_H */
