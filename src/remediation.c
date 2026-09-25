/*
 * remediation.c — rule_id → 修复建议映射
 */
#include "remediation.h"
#include <string.h>

struct Remap {
    const char *rule_id;
    const char *fix;
};

static const struct Remap TABLE[] = {
    { "IFA-ACC-001", "删除空口令账号，或在 /etc/shadow 中为其设置强随机密码并锁定" },
    { "IFA-ACC-002", "把 MD5 哈希替换为 sha512crypt(openssl passwd -6)；禁止 DES/MD5 口令" },
    { "IFA-ACC-003", "哈希不应明文存于 /etc/passwd；改为 x 并移到 /etc/shadow，权限 600" },
    { "IFA-SEC-001", "删除硬编码密钥；改用编译期注入或首次启动随机生成；轮换已泄露凭证" },
    { "IFA-PERM-001", "移除非必要 SUID 程序；必须保留的用能力(capabilities)替代 SUID" },
    { "IFA-BOOT-001", "禁用 telnetd 等明文服务；用 dropbear/OpenSSH；删除 init 脚本里的反向 shell" },
    { "IFA-NET-001", "对外服务加认证；管理端口只监听 LAN 接口；关闭不必要服务" },
    { "IFA-FS-001", "chmod o-w；配置文件改 644，二进制 755；排查是否已被植入" },
    { "IFA-SSH-001", "PermitRootLogin no；PasswordAuthentication 按需关闭；用密钥登录" },
    { "IFA-PERM-002", "chmod 600 /etc/shadow；属主 root:shadow" },
    { "IFA-PERM-003", "chmod 644 /etc/passwd；任何人不应可写" },
    { "IFA-WEB-001", "从 web 根目录删除 .bak/.old/备份文件；备份不随固件发布" },
    { "IFA-WEB-002", "cgi-bin 脚本改 755；上传目录禁止执行权限" },
    { "IFA-CRACK-001", "口令已被字典破解：立即更换为 16 位随机口令并全设备轮换" },
};

const char *remediation_for(const char *rule_id)
{
    for (size_t i = 0; i < sizeof(TABLE)/sizeof(TABLE[0]); i++) {
        if (strcmp(TABLE[i].rule_id, rule_id) == 0) return TABLE[i].fix;
    }
    return "查看厂商安全公告并更新到最新固件";
}
