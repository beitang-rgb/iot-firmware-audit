/*
 * rules_ssh.h — SSH 服务弱配置检测
 */
#ifndef IFA_RULES_SSH_H
#define IFA_RULES_SSH_H
#include "audit.h"

/* 扫描 <root>/etc/ssh/sshd_config（含 ssh_config 目录变体），
 * 检测允许 root 直接登录、允许空密码、启用明文密码等弱项。
 * 返回发现的条数。 */
int audit_ssh_config(AuditReport *rep, const char *root);

/* 纯函数：判断一行 sshd 配置是否属于弱配置，命中填 out */
int ssh_config_line_weak(const char *line, Finding *out);

#endif
