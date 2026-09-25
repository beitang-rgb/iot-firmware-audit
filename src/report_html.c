/*
 * report_html.c — 把 AuditReport 渲染成独立 HTML
 */
#include "report_html.h"
#include "remediation.h"
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
          ".toolbar{margin:12px 0}"
          ".toolbar button{padding:6px 14px;margin-right:8px;border:1px solid #34495e;background:#34495e;color:#fff;border-radius:4px;cursor:pointer;font-size:13px}"
          ".toolbar button:hover{background:#2c3e50}"
          ".group-header th{background:#ecf0f1;cursor:pointer;font-weight:600;color:#2c3e50}"
          ".group-header:hover th{background:#dfe6e9}"
          "</style></head><body>", fp);

    fputs("<h1>IoT 固件 rootfs 安全审计报告</h1>", fp);
    fputs("<p>rootfs: <code>", fp);
    html_esc(rep->root_dir, fp);
    fprintf(fp, "</code> · 扫描文件 %d · 发现 %d 项</p>",
            rep->files_scanned, rep->count);

    fputs("<div class=\"cards\">", fp);
    fprintf(fp, "<div class=\"card\" style=\"background:#c0392b\">CRITICAL %d</div>", crit);
    fprintf(fp, "<div class=\"card\" style=\"background:#e67e22\">HIGH %d</div>", high);
    fprintf(fp, "<div class=\"card\" style=\"background:#f39c12;color:#222\">MEDIUM %d</div>", med);
    fprintf(fp, "<div class=\"card\" style=\"background:#27ae60\">总数 %d</div>", rep->count);
    fputs("</div>", fp);

    if (rep->count == 0) {
        fputs("<p style='color:#27ae60;font-weight:600'>未发现已知规则命中的问题。</p>", fp);
    } else {
        fputs("<div class=\"toolbar\">"
              "<button id=\"btn-sev\" type=\"button\">展开低危/中危</button>"
              "<button id=\"btn-group\" type=\"button\">按规则分组</button>"
              "</div>", fp);

        fputs("<table><thead><tr><th>严重度</th><th>规则</th><th>位置</th>"
              "<th>说明</th><th>证据</th><th>修复建议</th></tr></thead>"
              "<tbody id=\"tbody\">", fp);
        for (int i = 0; i < rep->count; i++) {
            const Finding *f = &rep->items[i];
            fputs("<tr data-sev=\"", fp);
            fputs(severity_str(f->severity), fp);
            fputs("\" data-rule=\"", fp);
            html_esc(f->rule_id, fp);
            fputs("\"><td><span class=\"sev\" style=\"background:", fp);
            fputs(sev_color(f->severity), fp);
            fputs("\">", fp);
            fputs(severity_str(f->severity), fp);
            fputs("</span></td>", fp);
            fputs("<td>", fp);
            html_esc(f->rule_id, fp);
            fputs("</td><td>", fp);
            html_esc(f->file_path, fp);
            if (f->line > 0) fprintf(fp, ":%ld", f->line);
            fputs("</td>", fp);
            fputs("<td>", fp); html_esc(f->description, fp); fputs("</td>", fp);
            fputs("<td>", fp); html_esc(f->detail, fp); fputs("</td>", fp);
            fputs("<td style=\"font-size:13px;color:#2c3e50\">", fp);
            html_esc(remediation_for(f->rule_id), fp);
            fputs("</td></tr>", fp);
        }
        fputs("</tbody></table>", fp);

        fputs(
"<script>\n"
"(function(){\n"
"  var tbody = document.getElementById('tbody');\n"
"  if (!tbody) return;\n"
"  var rows = Array.prototype.slice.call(tbody.querySelectorAll('tr[data-rule]'));\n"
"  var btnSev = document.getElementById('btn-sev');\n"
"  var btnGroup = document.getElementById('btn-group');\n"
"  var state = { showLowMed: false, grouped: false };\n"
"  var collapsedRules = {};\n"
"  function sevShown(sev){\n"
"    return state.showLowMed || sev === 'CRITICAL' || sev === 'HIGH';\n"
"  }\n"
"  function clearGroupHeaders(){\n"
"    var gh = tbody.querySelectorAll('tr.group-header');\n"
"    for (var i = 0; i < gh.length; i++) gh[i].parentNode.removeChild(gh[i]);\n"
"  }\n"
"  function render(){\n"
"    clearGroupHeaders();\n"
"    if (!state.grouped){\n"
"      for (var i = 0; i < rows.length; i++){\n"
"        tbody.appendChild(rows[i]);\n"
"        rows[i].style.display = sevShown(rows[i].getAttribute('data-sev')) ? '' : 'none';\n"
"      }\n"
"      return;\n"
"    }\n"
"    var order = [];\n"
"    var map = {};\n"
"    for (var i = 0; i < rows.length; i++){\n"
"      var rule = rows[i].getAttribute('data-rule');\n"
"      if (!map[rule]){ map[rule] = []; order.push(rule); }\n"
"      map[rule].push(rows[i]);\n"
"    }\n"
"    for (var g = 0; g < order.length; g++){\n"
"      var rule = order[g];\n"
"      var all = map[rule];\n"
"      var vis = [];\n"
"      for (var j = 0; j < all.length; j++){\n"
"        if (sevShown(all[j].getAttribute('data-sev'))) vis.push(all[j]);\n"
"      }\n"
"      if (vis.length === 0) continue;\n"
"      var collapsed = !!collapsedRules[rule];\n"
"      var header = document.createElement('tr');\n"
"      header.className = 'group-header';\n"
"      var th = document.createElement('th');\n"
"      th.colSpan = 6;\n"
"      var label = document.createElement('span');\n"
"      label.textContent = (collapsed ? '\\u25B8 ' : '\\u25BE ') + rule + ' (' + vis.length + ')';\n"
"      th.appendChild(label);\n"
"      header.appendChild(th);\n"
"      tbody.appendChild(header);\n"
"      for (var j = 0; j < vis.length; j++){\n"
"        tbody.appendChild(vis[j]);\n"
"        vis[j].style.display = collapsed ? 'none' : '';\n"
"      }\n"
"      header.addEventListener('click', (function(r, vs, lbl){\n"
"        return function(){\n"
"          collapsedRules[r] = !collapsedRules[r];\n"
"          var c = !!collapsedRules[r];\n"
"          for (var k = 0; k < vs.length; k++) vs[k].style.display = c ? 'none' : '';\n"
"          lbl.textContent = (c ? '\\u25B8 ' : '\\u25BE ') + r + ' (' + vs.length + ')';\n"
"        };\n"
"      })(rule, vis, label));\n"
"    }\n"
"  }\n"
"  if (btnSev) btnSev.addEventListener('click', function(){\n"
"    state.showLowMed = !state.showLowMed;\n"
"    btnSev.textContent = state.showLowMed ? '折叠低危/中危' : '展开低危/中危';\n"
"    render();\n"
"  });\n"
"  if (btnGroup) btnGroup.addEventListener('click', function(){\n"
"    state.grouped = !state.grouped;\n"
"    btnGroup.textContent = state.grouped ? '平铺显示' : '按规则分组';\n"
"    render();\n"
"  });\n"
"  render();\n"
"})();\n"
"</script>", fp);
    }
    fputs("</body></html>", fp);
    fclose(fp);
    return 0;
}
