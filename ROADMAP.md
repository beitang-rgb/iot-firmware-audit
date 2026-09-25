# iot-firmware-audit — 产品路线图

对标 EMBA（87 模块）/ FirmAE（动态模拟）/ FAT（自动化包装）。
当前定位：**静态 rootfs 安全审计 CLI**，不做 QEMU 动态模拟（那是博士论文量级）。

## 当前版本 v0.7（已完成）

**11 条规则**，对标 EMBA 的 P/S 模块：

| 模块 | 规则 | 检测内容 |
|---|---|---|
| account | ACC-001/002/003 | 空口令、MD5 弱哈希、passwd 存哈希 |
| secrets | SEC-001 | 硬编码 password/token/私钥/PSK |
| suid | PERM-001 | SUID/SGID 提权文件 |
| boot | BOOT-001 | telnetd/反向 shell 后门 |
| network | NET-001 | 无认证对外服务 |
| worldwritable | FS-001 | o+w 文件 |
| ssh | SSH-001 | PermitRootLogin/空密码 |
| perms | PERM-002/003 | shadow/passwd 权限过宽 |
| web | WEB-001/002 | 备份文件暴露/cgi-bin 可写 |
| **crack** | **CRACK-001** | **离线字典破解出厂弱口令** |
| **components** | **COMP-001** | **BusyBox/OpenSSL 旧版本 → CVE** |

工程基线：
- 纯 C99，无第三方依赖（除 libcrypt）
- 函数指针注册表，加规则不改 scanner
- 25 单元测试 + 15 条端到端集成断言
- cppcheck 零报告，CI 三阶段（静态分析→构建→测试）
- text / JSON / HTML 三种报告，每条 finding 带修复建议
- --extract 模式：binwalk 解包后自动扫

## v0.8 — 可用性打磨（2 周内）

- [ ] 支持 jffs2/ubifs rootfs（现在只认 squashfs-root）
- [ ] HTML 报告加严重度统计卡片和可折叠明细
- [ ] --exclude 排除目录参数
- [ ] README 重写：一个真实路由器固件扫出 N 个 HIGH 的叙事
- [ ] 加 --version 输出编译时间和 commit hash

## v0.9 — 真实固件验证（1 个月内）

- [ ] 找 3 个真实开源路由器固件（OpenWrt/老小米/老 TP-Link）跑一遍
- [ ] 对比 EMBA 在同一份固件上的输出，记录漏报/误报
- [ ] 输出一份"对真实固件的审计报告"作为 README 案例
- [ ] 处理二进制误报（.so/.db 跳过）

## v1.0 — 企业级标准

- [ ] CVE 库从硬编码 8 条扩到从 NVD JSON 拉取
- [ ] 输出 SARIF（GitHub Code Scanning 原生格式），能直接贴进 PR
- [ ] 规则文档：每条规则一条 docs/rule-xxx.md，配 CWE 编号
- [ ] 打包 deb/rpm，apt 一行安装
- [ ] 性能：大固件（>200MB）扫描时间 < 30s

## 明确不做的事（边界）

- QEMU 动态模拟（FirmAE 路线）——学术研究方向，不是 CLI 工具
- 固件加解密/解包加密镜像
- 二进制反汇编/Ghidra 集成（用 strings 级别够了）
- Web UI（HTML 报告已经够）

## 市场定位

给固件厂商安全团队、IoT penetration tester 用的**第一道快筛**：
5 分钟跑完一个固件，告诉你"这里有 CRITICAL，去深研"。
不替代 Ghidra/EMBA，替代"人工 grep passwd"。
