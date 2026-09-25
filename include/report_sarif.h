/*
 * report_sarif.h — SARIF 2.1.0 报告输出
 *
 * SARIF (Static Analysis Results Interchange Format) 是 OASIS 标准，
 * 被 GitHub Code Scanning、GitLab SAST、VS Code 等原生支持。
 * 输出 .sarif 文件即可在 CI 中直接上传做代码扫描门禁。
 */
#ifndef IFA_REPORT_SARIF_H
#define IFA_REPORT_SARIF_H

#include "audit.h"

/*
 * 把 AuditReport 渲染为 SARIF 2.1.0 JSON 写入 out_path。
 * 成功返回 0，失败(无法打开文件)返回 -1。
 */
int report_write_sarif(const AuditReport *rep, const char *out_path);

#endif
