/*
 * report.h — 报告渲染(text / json)
 */
#ifndef IFA_REPORT_H
#define IFA_REPORT_H

#include "audit.h"

/*
 * 把报告渲染到指定文件流(format 取 "text" 或 "json")。
 * out 为已打开的文件指针(可为 stdout)。
 */
void report_render(const AuditReport *rep, const char *format, void *out);

#endif /* IFA_REPORT_H */
