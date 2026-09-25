/*
 * audit.c — Finding / AuditReport 的基础操作
 */
#include "audit.h"
#include <string.h>
#include <stdio.h>

void report_init(AuditReport *rep, const char *root_dir)
{
    if (!rep) return;
    memset(rep, 0, sizeof(*rep));
    if (root_dir) {
        snprintf(rep->root_dir, sizeof(rep->root_dir), "%s", root_dir);
    }
}

int report_add(AuditReport *rep, const Finding *f)
{
    if (!rep || !f) return -1;
    if (rep->count >= IFA_MAX_FINDINGS) return -1;

    Finding *dst = &rep->items[rep->count];
    /* 逐字段拷贝，避免结构体里的指针别名 */
    snprintf(dst->rule_id, sizeof(dst->rule_id), "%s", f->rule_id);
    dst->severity   = f->severity;
    snprintf(dst->category, sizeof(dst->category), "%s", f->category);
    snprintf(dst->file_path, sizeof(dst->file_path), "%s", f->file_path);
    dst->line       = f->line;
    snprintf(dst->description, sizeof(dst->description), "%s", f->description);
    snprintf(dst->detail, sizeof(dst->detail), "%s", f->detail);

    rep->count++;
    return 0;
}

const char *severity_str(Severity s)
{
    switch (s) {
        case SEV_INFO:     return "INFO";
        case SEV_LOW:      return "LOW";
        case SEV_MEDIUM:   return "MEDIUM";
        case SEV_HIGH:     return "HIGH";
        case SEV_CRITICAL: return "CRITICAL";
        default:           return "UNKNOWN";
    }
}

int report_count_at_least(const AuditReport *rep, Severity s)
{
    if (!rep) return 0;
    int n = 0;
    for (int i = 0; i < rep->count; i++) {
        if (rep->items[i].severity >= s) n++;
    }
    return n;
}
