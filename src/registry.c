/*
 * registry.c — 规则注册表：把各规则模块包装成统一入口并集中登记
 */
#include "registry.h"
#include "rules_account.h"
#include "rules_secrets.h"
#include "rules_suid.h"
#include "rules_boot.h"
#include "rules_net.h"
#include "rules_worldwritable.h"
#include "rules_ssh.h"
#include "rules_perms.h"
#include "rules_web.h"
#include <stdio.h>

/* 以下 wrapper 把"路径拼接"这种和规则无关的样板代码收在这里，
 * 规则模块本身只关心怎么判断一行/一个文件。 */

static int rule_account(AuditReport *rep, const char *root)
{
    char p[1024];
    snprintf(p, sizeof(p), "%s/etc/shadow", root);
    int n = audit_shadow_file(rep, p);
    snprintf(p, sizeof(p), "%s/etc/passwd", root);
    n += audit_passwd_file(rep, p);
    return n;
}

static int rule_secrets(AuditReport *rep, const char *root)
{
    char p[1024];
    snprintf(p, sizeof(p), "%s/etc", root);
    return audit_secrets_in_dir(rep, p);
}

/* suid/boot/net/worldwritable/ssh/perms/web 本身就是 (rep, root) 签名，直接登记 */

/* 规则表：新增规则就在这里加一行 */
static const RuleEntry RULES[] = {
    { "account",       rule_account },
    { "secrets",       rule_secrets },
    { "suid",          audit_suid_tree },
    { "boot",          audit_boot_scripts },
    { "network",       audit_listening_services },
    { "worldwritable", audit_worldwritable },
    { "ssh",           audit_ssh_config },
    { "perms",         audit_sensitive_perms },
    { "web",           audit_web_exposures },
};
#define N_RULES (int)(sizeof(RULES) / sizeof(RULES[0]))

int registry_run_all(AuditReport *rep, const char *root)
{
    int total = 0;
    for (int i = 0; i < N_RULES; i++) {
        total += RULES[i].run(rep, root);
    }
    return total;
}

void registry_list(void)
{
    printf("已注册 %d 条规则:\n", N_RULES);
    for (int i = 0; i < N_RULES; i++) {
        printf("  - %s\n", RULES[i].name);
    }
}
