/*
 * report_html.c — 把 AuditReport 渲染成独立 HTML
 */
#include "report_html.h"
#include <stdio.h>
#include <string.h>

static const char *sev_color(Severity s)
{
    switch (s) {
        case SEV_CRITICAL: return "#c0392b";
        case SEV_HIGH:     return "#e67e22";
        case SEV_MEDIUM:   return "#f1c40f";
        case SEV_LOW:      return "#3498db";
        default:           return "#95a5a6";
    }
}

static void html_esc(const char *s, FILE *out)
{
    for (; *s; s++) {
        switch (*s) {
            case '<': fputs("&lt;", out); break;
            case '>': fputs("&gt;", out); break;
            case '&': fputs("&amp;", out); break;
            case '"': fputs("&quot;", out); break;
            default:  fputc(*s, out);
        }
    }
}

int report_write_html(const AuditReport *rep, const char *out_path)
{
    FILE *fp = fopen(out_path, "w");
    if (!fp) return -1;

    int crit = report_count_at_least(rep, SEV_CRITICAL);
    int high = report_count_at_least(rep, SEV_HIGH);
    int med  = report_count_at_least(rep, SEV_MEDIUM);

    fputs("<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">"
          "<title>IoT 固件审计报告</title><style>"
          "body{font-family:-apple-system,'Segoe UI',sans-serif;margin:24px;background:#f7f9fa;color:#222}"
          "h1{font-size:22px}.cards{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}"
          ".card{padding:14px 20px;border-radius:8px;color:#fff;font-weight:600;min-width:120px}"
          "table{border-collapse:collapse;width:100%;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.1)}"
          "th,td{padding:8px 10px;border-bottom:1px solid #eee;text-align:left;font-size:14px}"
          "th{background:#34495e;color:#fff}.sev{padding:2px 8px;border-radius:4px;color:#fff;font-size:12px}"
          "</style></head><body>", fp);

    fputs("<h1>IoT 固件 rootfs 安全审计报告</h1>", fp);
    fprintf(fp, "<p>rootfs: <code>%s</code> · 扫描文件 %d · 发现 %d 项</p>",
            rep->root_dir, rep->files_scanned, rep->count);

    fputs("<div class=\"cards\">", fp);
    fprintf(fp, "<div class=\"card\" style=\"background:#c0392b\">CRITICAL %d</div>", crit);
    fprintf(fp, "<div class=\"card\" style=\"background:#e67e22\">HIGH %d</div>", high);
    fprintf(fp, "<div class=\"card\" style=\"background:#f39c12;color:#222\">MEDIUM %d</div>", med);
    fprintf(fp, "<div class=\"card\" style=\"background:#27ae60\">总数 %d</div>", rep->count);
    fputs("</div>", fp);

    if (rep->count == 0) {
        fputs("<p style='color:#27ae60;font-weight:600'>未发现已知规则命中的问题。</p>", fp);
    } else {
        fputs("<table><tr><th>严重度</th><th>规则</th><th>位置</th><th>说明</th><th>证据</th></tr>", fp);
        for (int i = 0; i < rep->count; i++) {
            const Finding *f = &rep->items[i];
            fprintf(fp, "<tr><td><span class=\"sev\" style=\"background:%s\">%s</span></td>",
                    sev_color(f->severity), severity_str(f->severity));
            fprintf(fp, "<td>%s</td>", f->rule_id);
            fprintf(fp, "<td>%s", f->file_path);
            if (f->line > 0) fprintf(fp, ":%ld", f->line);
            fputs("</td>", fp);
            fputs("<td>", fp); html_esc(f->description, fp); fputs("</td>", fp);
            fputs("<td>", fp); html_esc(f->detail, fp); fputs("</td></tr>", fp);
        }
        fputs("</table>", fp);
    }
    fputs("</body></html>", fp);
    fclose(fp);
    return 0;
}
