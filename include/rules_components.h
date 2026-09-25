/*
 * rules_components.h — 组件版本/CVE 识别
 */
#ifndef IFA_RULES_COMPONENTS_H
#define IFA_RULES_COMPONENTS_H
#include "audit.h"

int parse_busybox_version(const char *buf, long buf_len, int *out_major, int *out_minor);
int audit_components(AuditReport *rep, const char *root);

#endif
