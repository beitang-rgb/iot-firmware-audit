/*
 * report.c — 把 AuditReport 渲染为人类可读文本或 JSON
 */
#include "report.h"
#include "remediation.h"
#include <stdio.h>
#include <string.h>

/* 把一个字符串做最小 JSON 转义后写入流 */
static void json_esc(const char *s, FILE *out)
{
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
            case '"':  fputs("\\\"", out); break;
            case '\\': fputs("\\\\", out); break;
            case '\n': fputs("\\n", out); break;
            case '\t': fputs("\\t", out); break;
            default:
                if (c < 0x20) fprintf(out, "\\u%04x", c);
                else          fputc(c, out);
        }
    }
}

static void render_text(const AuditReport *rep, FILE *out)
{
    fprintf(out, "==============================================\n");
    fprintf(out, " iot-firmware-audit 安全审计报告\n");
    fprintf(out, "----------------------------------------------\n");
    fprintf(out, " 根目录      : %s\n", rep->root_dir);
    fprintf(out, " 扫描文件数  : %d\n", rep->files_scanned);
    fprintf(out, " 发现总数    : %d\n", rep->count);
    fprintf(out, "   CRITICAL  : %d\n", report_count_at_least(rep, SEV_CRITICAL));
    fprintf(out, "   HIGH      : %d\n", report_count_at_least(rep, SEV_HIGH));
    fprintf(out, "   MEDIUM    : %d\n", report_count_at_least(rep, SEV_MEDIUM));
    fprintf(out, "==============================================\n\n");

    if (rep->count == 0) {
        fprintf(out, "未发现已知规则命中的问题。\n");
        return;
    }

    for (int i = 0; i < rep->count; i++) {
        const Finding *f = &rep->items[i];
        fprintf(out, "[%s] %s (%s)\n",
                severity_str(f->severity), f->rule_id, f->category);
        fprintf(out, "    位置 : %s", f->file_path);
        if (f->line > 0) fprintf(out, ":%ld", f->line);
        fprintf(out, "\n");
        fprintf(out, "    描述 : %s\n", f->description);
        fprintf(out, "    证据 : %s\n", f->detail);
        fprintf(out, "    修复 : %s\n\n", remediation_for(f->rule_id));
    }
}

static void render_json(const AuditReport *rep, FILE *out)
{
    fprintf(out, "{\n");
    fprintf(out, "  \"tool\": \"iot-firmware-audit\",\n");
    fprintf(out, "  \"version\": \"%s\",\n", IFA_VERSION);
    fprintf(out, "  \"root_dir\": \"");
    json_esc(rep->root_dir, out);
    fprintf(out, "\",\n");
    fprintf(out, "  \"summary\": {\n");
    fprintf(out, "    \"files_scanned\": %d,\n", rep->files_scanned);
    fprintf(out, "    \"total\": %d,\n", rep->count);
    fprintf(out, "    \"critical\": %d,\n", report_count_at_least(rep, SEV_CRITICAL));
    fprintf(out, "    \"high\": %d,\n", report_count_at_least(rep, SEV_HIGH));
    fprintf(out, "    \"medium\": %d\n", report_count_at_least(rep, SEV_MEDIUM));
    fprintf(out, "  },\n");
    fprintf(out, "  \"findings\": [\n");

    for (int i = 0; i < rep->count; i++) {
        const Finding *f = &rep->items[i];
        fprintf(out, "    {\n");
        fprintf(out, "      \"rule_id\": \"");   json_esc(f->rule_id, out);     fprintf(out, "\",\n");
        fprintf(out, "      \"severity\": \"");   fputs(severity_str(f->severity), out); fprintf(out, "\",\n");
        fprintf(out, "      \"category\": \"");   json_esc(f->category, out);    fprintf(out, "\",\n");
        fprintf(out, "      \"file\": \"");       json_esc(f->file_path, out);   fprintf(out, "\",\n");
        fprintf(out, "      \"line\": %ld,\n", f->line);
        fprintf(out, "      \"description\": \""); json_esc(f->description, out); fprintf(out, "\",\n");
        fprintf(out, "      \"detail\": \"");     json_esc(f->detail, out);      fprintf(out, "\",\n");
        fprintf(out, "      \"remediation\": \""); json_esc(remediation_for(f->rule_id), out); fprintf(out, "\"\n");
        fprintf(out, "    }%s\n", (i + 1 < rep->count) ? "," : "");
    }
    fprintf(out, "  ]\n");
    fprintf(out, "}\n");
}

void report_render(const AuditReport *rep, const char *format, void *out)
{
    FILE *fp = (FILE *)out;
    if (format && strcmp(format, "json") == 0) {
        render_json(rep, fp);
    } else {
        render_text(rep, fp);
    }
}
