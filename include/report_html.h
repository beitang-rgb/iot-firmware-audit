/*
 * report_html.h — HTML 可视化报告
 */
#ifndef IFA_REPORT_HTML_H
#define IFA_REPORT_HTML_H
#include "audit.h"

/* 把报告写成独立 HTML 文件(内联 CSS)。成功返回 0。 */
int report_write_html(const AuditReport *rep, const char *out_path);

#endif
