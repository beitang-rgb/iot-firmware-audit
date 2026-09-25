/*
 * rules_net.h — 对外暴露服务/监听端口检测
 */
#ifndef IFA_RULES_NET_H
#define IFA_RULES_NET_H
#include "audit.h"

/* 扫描 root 下启动脚本中无认证对外服务(telnetd/ftpd/nc -l)。 */
int audit_listening_services(AuditReport *rep, const char *root);

#endif
