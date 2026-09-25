# iot-firmware-audit v0.9 安全代码审查报告

- **审查对象**: `D:\projects\iot-firmware-audit` @ v0.9.0
- **审查日期**: 2026-09-25
- **审查方式**: 只读静态审查（独立 agent 全量过审）
- **审查范围**: `src/` 下全部 .c 文件 + `include/` 下全部头文件

---

## 摘要

共发现 **12 个真实问题**，其中 3 HIGH 已在 v0.9 全部修复，剩余 5 MEDIUM / 4 LOW 记录在案。

| 严重度 | 总数 | 已修复 | 遗留 |
|--------|------|--------|------|
| CRITICAL | 0 | - | - |
| HIGH | 3 | 3 | 0 |
| MEDIUM | 5 | 0 | 5 |
| LOW | 4 | 0 | 4 |

**无远程代码执行漏洞**，无缓冲区越界写。主要风险：符号链接跟随、栈缓冲、超长行拆分。

---

## 已修复的 HIGH（v0.9）

1. **rules_boot.c / rules_net.c**: `stat()` → `lstat()` + `S_ISLNK` 跳过，防止恶意固件符号链接读取宿主文件
2. **rules_components.c**: 256KB 栈缓冲 → `malloc`/`free` 堆分配，避免与栈上 AuditReport 叠加爆栈

## 遗留 MEDIUM（v1.0+）

- rules_ssh.c / rules_perms.c: stat→lstat
- fgets 超长行拆分绕过规则（需消费行尾）
- extract --extract 成功后临时目录不清理
- rules_account.c buf[1024] 截断 2048 字节行

## 遗留 LOW（v1.x+）

- extract.c rmtree 用 system() 而非递归 unlink
- rules_crack.c buf[1024] 截断
- 路径缓冲区大小不一致 + -Wno-format-truncation
- crypt() 不可重入（当前单线程安全）

## 无问题确认

audit.c / scanner.c / registry.c / report.c / report_html.c / remediation.c /
rules_suid.c / rules_worldwritable.c / rules_web.c / cli.c — 无真实安全 bug。
