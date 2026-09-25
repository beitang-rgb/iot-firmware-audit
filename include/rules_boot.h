/*
 * rules_boot.h — 可疑启动项规则
 * 审计 /etc/init.d/、/etc/rcS、/etc/rc.local 中可疑的服务自启动
 * (如无认证 telnetd、netcat 监听、反向 shell 等后门特征)。
 */
#ifndef IFA_RULES_BOOT_H
#define IFA_RULES_BOOT_H

#include "audit.h"

/* 扫描 rootfs 下常见的启动脚本位置。返回写入条数。 */
int audit_boot_scripts(AuditReport *rep, const char *root);

/*
 * 纯函数：判断一行启动脚本内容是否命中可疑后门特征。
 * 命中时把命中特征写入 out_detail，返回 1；否则 0。
 */
int line_is_suspicious_boot(const char *line, char *out_detail, size_t out_size);

#endif /* IFA_RULES_BOOT_H */
