/*
 * rules_web.h — Web 暴露面规则
 *
 * IoT 路由器/web 摄像头常见问题：
 *  1. 配置备份文件(.bak / config.tar.gz)放在 web 根目录，攻击者可直接下载拿到密码；
 *  2. /www/cgi-bin/ 下的脚本全局可写，攻击者可替换成后门。
 */
#ifndef IFA_RULES_WEB_H
#define IFA_RULES_WEB_H

#include "audit.h"

/* 扫描 <root>/www/ 下的危险暴露。返回写入条数。 */
int audit_web_exposures(AuditReport *rep, const char *root);

#endif /* IFA_RULES_WEB_H */
