/*
 * report_sarif.c — 把 AuditReport 渲染为 SARIF 2.1.0 JSON
 *
 * 设计要点：
 *  - 规则元数据(ruleId/name/shortDescription/defaultConfiguration/help)
 *    集中在 RULE_META 表，新增规则时在此加一行；
 *  - 所有用户可控字符串走 sarif_esc() 做 JSON 转义，与 report.c 的 json_esc 同思路；
 *  - 严重度映射：CRITICAL/HIGH → error，MEDIUM → warning，LOW/INFO → note；
 *  - locations.physicalLocation.artifactLocation.uri 用相对 rootfs 的路径，
 *    uriBaseId 设为 ROOTFS，方便 SARIF 消费者做路径重写。
 */
#include "report_sarif.h"
#include "remediation.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

/* ---- 规则元数据表 ---- */

typedef struct {
    const char *rule_id;
    const char *name;            /* PascalCase 短名，SARIF rule.name */
    const char *short_desc;      /* 一句话描述 */
    const char *default_level;   /* error / warning / note */
} RuleMeta;

static const RuleMeta RULE_META[] = {
    { "IFA-ACC-001",  "WeakOrEmptyPassword",     "shadow 空口令/弱哈希/疑似明文", "error"   },
    { "IFA-ACC-002",  "HashInPasswd",            "口令哈希存放在 /etc/passwd",   "warning" },
    { "IFA-SEC-001",  "HardcodedSecret",         "配置文件中硬编码密码/密钥/Token", "warning" },
    { "IFA-PERM-001", "SuidBinary",              "SUID/SGID 可执行文件(提权风险)", "error"   },
    { "IFA-BOOT-001", "SuspiciousBootService",   "启动脚本中可疑服务/后门特征",   "error"   },
    { "IFA-NET-001",  "UnauthenticatedService",  "启动脚本暴露无认证对外服务",    "warning" },
    { "IFA-FS-001",   "WorldWritableFile",       "全局可写文件",                  "note"    },
    { "IFA-SSH-001",  "WeakSshConfig",           "SSH 弱配置(root登录/空密码)",   "warning" },
    { "IFA-PERM-002", "ShadowPermsTooWide",      "/etc/shadow 权限过宽",          "error"   },
    { "IFA-PERM-003", "PasswdWorldWritable",     "/etc/passwd 全局可写",          "warning" },
    { "IFA-WEB-001",  "WebBackupExposed",        "web 根目录暴露配置备份文件",    "error"   },
    { "IFA-WEB-002",  "CgiBinWorldWritable",     "cgi-bin 脚本全局可写",          "error"   },
    { "IFA-CRACK-001","CrackedPassword",         "出厂弱口令字典破解命中",        "error"   },
    { "IFA-COMP-001", "VulnerableComponent",     "组件版本存在已知 CVE",          "error"   },
};
#define N_RULE_META (int)(sizeof(RULE_META) / sizeof(RULE_META[0]))

static const RuleMeta *find_rule_meta(const char *rule_id)
{
    for (int i = 0; i < N_RULE_META; i++) {
        if (strcmp(RULE_META[i].rule_id, rule_id) == 0) return &RULE_META[i];
    }
    return NULL;
}

/* 严重度 → SARIF level */
static const char *sev_to_sarif_level(Severity s)
{
    switch (s) {
        case SEV_CRITICAL: return "error";
        case SEV_HIGH:     return "error";
        case SEV_MEDIUM:   return "warning";
        case SEV_LOW:      return "note";
        default:           return "note";
    }
}

/* JSON 字符串转义（与 report.c 的 json_esc 一致，独立实现避免跨模块依赖） */
static void sarif_esc(const char *s, FILE *out)
{
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
            case '"':  fputs("\\\"", out); break;
            case '\\': fputs("\\\\", out); break;
            case '\n': fputs("\\n", out); break;
            case '\t': fputs("\\t", out); break;
            case '\r': fputs("\\r", out); break;
            case '\b': fputs("\\b", out); break;
            case '\f': fputs("\\f", out); break;
            default:
                if (c < 0x20) fprintf(out, "\\u%04x", c);
                else          fputc(c, out);
        }
    }
}

/* 获取当前 UTC 时间字符串（ISO 8601），写入 buf */
static void utc_now(char *buf, size_t sz)
{
    time_t t = time(NULL);
    struct tm tm_utc;
#if defined(_WIN32)
    gmtime_s(&tm_utc, &t);
#else
    gmtime_r(&t, &tm_utc);
#endif
    strftime(buf, sz, "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
}

int report_write_sarif(const AuditReport *rep, const char *out_path)
{
    if (!rep || !out_path) return -1;

    FILE *fp = fopen(out_path, "w");
    if (!fp) return -1;

    char timestamp[32];
    utc_now(timestamp, sizeof(timestamp));

    /* ---- SARIF 头部 ---- */
    fputs("{\n", fp);
    fputs("  \"$schema\": \"https://json.schemastore.org/sarif-2.1.0.json\",\n", fp);
    fputs("  \"version\": \"2.1.0\",\n", fp);
    fputs("  \"runs\": [\n", fp);
    fputs("    {\n", fp);

    /* ---- tool.driver ---- */
    fputs("      \"tool\": {\n", fp);
    fputs("        \"driver\": {\n", fp);
    fputs("          \"name\": \"iot-firmware-audit\",\n", fp);
    fprintf(fp, "          \"version\": \"%s\",\n", IFA_VERSION);
    fputs("          \"informationUri\": \"https://github.com/beitang-rgb/iot-firmware-audit\",\n", fp);
    fputs("          \"semanticVersion\": \"", fp);
    fputs(IFA_VERSION, fp);
    fputs("\",\n", fp);

    /* ---- rules 数组：只输出报告中实际出现过的规则 ---- */
    fputs("          \"rules\": [\n", fp);
    {
        int emitted[N_RULE_META];
        memset(emitted, 0, sizeof(emitted));
        /* 先标记哪些规则在结果中出现了 */
        for (int i = 0; i < rep->count; i++) {
            const RuleMeta *m = find_rule_meta(rep->items[i].rule_id);
            if (m) {
                int idx = (int)(m - RULE_META);
                emitted[idx] = 1;
            }
        }
        int first = 1;
        for (int i = 0; i < N_RULE_META; i++) {
            if (!emitted[i]) continue;
            if (!first) fputs(",\n", fp);
            first = 0;
            const RuleMeta *m = &RULE_META[i];
            fputs("            {\n", fp);
            fprintf(fp, "              \"id\": \"%s\",\n", m->rule_id);
            fprintf(fp, "              \"name\": \"%s\",\n", m->name);
            fputs("              \"shortDescription\": { \"text\": \"", fp);
            sarif_esc(m->short_desc, fp);
            fputs("\" },\n", fp);
            fprintf(fp, "              \"defaultConfiguration\": { \"level\": \"%s\" },\n", m->default_level);
            fputs("              \"help\": { \"text\": \"", fp);
            sarif_esc(remediation_for(m->rule_id), fp);
            fputs("\" },\n", fp);
            fputs("              \"helpUri\": \"https://github.com/beitang-rgb/iot-firmware-audit#rules\"\n", fp);
            fputs("            }", fp);
        }
        fputs("\n          ],\n", fp);
    }

    fputs("          \"properties\": {\n", fp);
    fprintf(fp, "            \"files_scanned\": %d,\n", rep->files_scanned);
    fprintf(fp, "            \"total_findings\": %d\n", rep->count);
    fputs("          }\n", fp);
    fputs("        }\n", fp);
    fputs("      },\n", fp);

    /* ---- invocations ---- */
    fputs("      \"invocations\": [\n", fp);
    fputs("        {\n", fp);
    fprintf(fp, "          \"executionSuccessful\": true,\n");
    fprintf(fp, "          \"endTimeUtc\": \"%s\",\n", timestamp);
    fputs("          \"workingDirectory\": { \"uri\": \"file:///", fp);
    sarif_esc(rep->root_dir, fp);
    fputs("\" }\n", fp);
    fputs("        }\n", fp);
    fputs("      ],\n", fp);

    /* ---- originalUriBaseIds ---- */
    fputs("      \"originalUriBaseIds\": {\n", fp);
    fputs("        \"ROOTFS\": { \"uri\": \"file:///", fp);
    sarif_esc(rep->root_dir, fp);
    fputs("/\" }\n", fp);
    fputs("      },\n", fp);

    /* ---- results ---- */
    fputs("      \"results\": [\n", fp);
    for (int i = 0; i < rep->count; i++) {
        const Finding *f = &rep->items[i];
        if (i > 0) fputs(",\n", fp);

        const RuleMeta *m = find_rule_meta(f->rule_id);
        int rule_index = m ? (int)(m - RULE_META) : -1;

        fputs("        {\n", fp);
        fprintf(fp, "          \"ruleId\": \"%s\",\n", f->rule_id);
        if (rule_index >= 0) {
            fprintf(fp, "          \"ruleIndex\": %d,\n", rule_index);
        }
        fprintf(fp, "          \"level\": \"%s\",\n", sev_to_sarif_level(f->severity));
        fputs("          \"message\": { \"text\": \"", fp);
        sarif_esc(f->description, fp);
        fputs("\" },\n", fp);

        /* locations */
        fputs("          \"locations\": [\n", fp);
        fputs("            {\n", fp);
        fputs("              \"physicalLocation\": {\n", fp);
        fputs("                \"artifactLocation\": {\n", fp);
        fputs("                  \"uri\": \"", fp);
        sarif_esc(f->file_path, fp);
        fputs("\",\n", fp);
        fputs("                  \"uriBaseId\": \"ROOTFS\"\n", fp);
        fputs("                },\n", fp);
        if (f->line > 0) {
            fprintf(fp, "                \"region\": { \"startLine\": %ld }\n", f->line);
        } else {
            fputs("                \"region\": { \"startLine\": 1 }\n", fp);
        }
        fputs("              }\n", fp);
        fputs("            }\n", fp);
        fputs("          ],\n", fp);

        /* properties: 保留 category / detail / severity 原始信息 */
        fputs("          \"properties\": {\n", fp);
        fputs("            \"category\": \"", fp);
        sarif_esc(f->category, fp);
        fputs("\",\n", fp);
        fprintf(fp, "            \"severity\": \"%s\",\n", severity_str(f->severity));
        fputs("            \"detail\": \"", fp);
        sarif_esc(f->detail, fp);
        fputs("\"\n", fp);
        fputs("          }\n", fp);

        fputs("        }", fp);
    }
    if (rep->count > 0) fputs("\n", fp);
    fputs("      ]\n", fp);

    /* ---- 收尾 ---- */
    fputs("    }\n", fp);
    fputs("  ]\n", fp);
    fputs("}\n", fp);

    fclose(fp);
    return 0;
}
