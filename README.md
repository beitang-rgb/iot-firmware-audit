# iot-firmware-audit (ifa)

[![CI](https://github.com/beitang-rgb/iot-firmware-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/beitang-rgb/iot-firmware-audit/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**一个用纯 C 写的 IoT 固件 rootfs 安全快筛工具。**
喂给它一个解包后的路由器固件，5 分钟内告诉你哪里有 CRITICAL。

```
$ ./ifa demo_rootfs

=== iot-firmware-audit v0.7.0 ===
rootfs: demo_rootfs
==============================================
 iot-firmware-audit 安全审计报告
----------------------------------------------
 根目录      : demo_rootfs
 扫描文件数  : 47
 发现总数    : 12
   CRITICAL  : 2
   HIGH      : 4
   MEDIUM    : 5
==============================================

[CRITICAL] IFA-ACC-001 (account)
    位置 : etc/shadow:1
    描述 : 账号 'admin' 存在空口令(shadow 第二字段为空)
    修复 : 删除空口令账号，或在 /etc/shadow 中为其设置强随机密码并锁定

[CRITICAL] IFA-CRACK-001 (account)
    位置 : etc/shadow
    描述 : 账号 'support' 的口令可被字典直接破解
    证据 : user=support password='admin'
    修复 : 口令已被字典破解：立即更换为 16 位随机口令并全设备轮换

[HIGH] IFA-COMP-001 (components)
    位置 : bin/busybox
    描述 : busybox 版本 1.19 存在已知漏洞 CVE-2011-2716
    证据 : HTTPd 目录遍历，可读任意文件
    修复 : 升级到该组件最新版；无法升级则在防火墙侧禁用对应服务
...
```

## 为什么需要它

路由器和 IoT 设备的固件里，最常见的洞不是 0day，而是**十年没人修的配置错误**：
空口令、硬编码密码、SUID 调试程序、telnetd 裸奔、cgi-bin 全局可写、BusyBox 停在 2011 年。
人工 `grep passwd` 一遍要半小时，还漏。`ifa` 把这道快筛自动化，告诉你"这里要去深研"。

**它不做** QEMU 动态模拟（那是 [FirmAE](https://github.com/pr0v3rbs/FirmAE) 的事）、
不做 Ghidra 反汇编、不替代 [EMBA](https://github.com/e-m-b-a/emba)（87 个模块的重型平台）。
它做的是 **EMBA 之前那一步**：解包后先跑一遍，5 分钟出结果。

## 功能

- 11 条规则，覆盖账户、硬编码密钥、SUID 提权、启动脚本后门、对外服务、SSH 弱配置、web 暴露面
- **离线字典破解**：对 shadow 里的 MD5/SHA 哈希跑 24 个 IoT 出厂弱口令，命中即报 CRITICAL
- **组件 CVE 匹配**：识别 BusyBox / OpenSSL 版本，关联已知 CVE（CVE-2011-2716、Heartbleed 等）
- 三种报告格式：text（终端）/ JSON（机器消费）/ 独立 HTML（带统计卡片和修复建议）
- `--extract` 模式：直接喂 `.bin` 固件，自动调 binwalk 解包再扫
- 每条 finding 附带**可执行的修复建议**，不是只报警

## 快速开始

```bash
# 依赖：gcc、make、libcrypt-dev（Debian/Ubuntu: sudo apt install libcrypt-dev）
make                # 编译

# 审计一个解包好的 rootfs
./ifa /path/to/squashfs-root/

# 三种输出
./ifa rootfs/ --text
./ifa rootfs/ --json report.json
./ifa rootfs/ --html report.html

# 直接扫原始固件（需要 binwalk）
./ifa --extract firmware.bin --html report.html

# 列出所有规则
./ifa --list-rules
```

## 规则一览

| 规则 | 类别 | 检测内容 | 严重度 |
|---|---|---|---|
| IFA-ACC-001 | 账户 | shadow 空口令 / MD5 弱哈希 / 疑似明文 | CRITICAL~MEDIUM |
| IFA-ACC-002 | 账户 | passwd 错误存放哈希 | MEDIUM |
| IFA-SEC-001 | 密钥 | /etc 下硬编码 password/token/私钥/PSK | MEDIUM~HIGH |
| IFA-CRACK-001 | 账户 | 出厂弱口令字典破解命中 | **CRITICAL** |
| IFA-PERM-001 | 提权 | SUID/SGID 文件（root 属主高危） | HIGH |
| IFA-BOOT-001 | 启动 | init.d 里 telnetd / 反向 shell 后门 | HIGH |
| IFA-NET-001 | 网络 | 无认证对外服务 | MEDIUM |
| IFA-SSH-001 | SSH | PermitRootLogin / 空密码 | MEDIUM |
| IFA-FS-001 | 文件 | o+w 全局可写文件 | LOW |
| IFA-PERM-002/003 | 文件 | shadow/passwd 权限过宽 | HIGH |
| IFA-WEB-001/002 | Web | /www 备份文件暴露 / cgi-bin 可写 | HIGH |
| IFA-COMP-001 | 组件 | BusyBox/OpenSSL 旧版本 → CVE | HIGH~MEDIUM |

## 工程实践

这个项目不是脚本拼装，是按 C 工程规范做的：

- **规则注册表**：函数指针表登记，加一条新规则只需在 `registry.c` 加一行
- **纯函数分离**：判定逻辑不碰文件系统，单元测试直接喂字符串
- **安全意识**：HTML 输出全量转义防 XSS；`--extract` 用 `fork+execvp` 不走 shell 防注入；递归遍历限深防栈溢出；临时目录用 `mkdtemp`
- **测试**：25 个单元断言 + 15 条端到端集成断言（在真实 Linux 文件系统上生成有漏洞的 rootfs 后扫描）
- **静态分析**：cppcheck 在 CI 里跑，零警告
- **CI**：GitHub Actions 三阶段——cppcheck → cmake 构建 → ctest + 集成测试

## 开发状态

见 [ROADMAP.md](ROADMAP.md)。当前 v0.7，下一步是真实固件验证和 SARIF 输出。

## 合规红线

本工具仅用于审计**你本人拥有或已获书面授权**的设备、公开发布的固件更新包、教学与 CTF。
禁止用于未授权测试。发现漏洞请走负责任披露流程通知厂商。

## License

MIT
