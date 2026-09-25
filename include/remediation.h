/*
 * remediation.h — 按 rule_id 给出可执行的修复建议
 *
 * 不加到 Finding 结构里（栈上已 2.7MB，再加字段迟早爆），
 * 而是渲染报告时按 rule_id 查表。这样集中管理，改一处全报告生效。
 */
#ifndef IFA_REMEDIATION_H
#define IFA_REMEDIATION_H

/* 返回该规则的修复建议；未知 rule_id 返回 "查看厂商安全公告" */
const char *remediation_for(const char *rule_id);

#endif
