# iot-firmware-audit (ifa)

[![CI](https://github.com/beitang-rgb/iot-firmware-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/beitang-rgb/iot-firmware-audit/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

轻量级 IoT 固件根文件系统安全审计命令行工具。
输入一个解包后的固件 rootfs（如 `squashfs-root/`），自动扫描常见安全问题并输出 text / JSON / HTML 报告。

> 设计目标：让物联网/嵌入式方向的学生在不依赖重型企业级平台的前提下，
> 用 C 完成一个真实可用的安全工具——同时作为学习 C、Linux、目录遍历、字符串处理的实战项目。

## 支持的规则

| 规则编号 | 类别 | 检测内容 | 严重度 |
|---|---|---|---|
| IFA-ACC-001 | account | `/etc/shadow` 空口令、弱哈希（MD5 $1$）、疑似明文 | CRITICAL~MEDIUM |
| IFA-ACC-002 | account | `/etc/passwd` 错误存放口令哈希 | MEDIUM |
| IFA-SEC-001 | secrets | `/etc` 下递归扫描硬编码 password/token/私钥/PSK | MEDIUM |
| IFA-PERM-001 | suid | 整树查找 SUID/SGID 提权文件（root 属主高危） | HIGH |
| IFA-PERM-002 | filesystem | `/etc/shadow` 权限过宽（应为 0600/0640） | HIGH |
| IFA-PERM-003 | filesystem | `/etc/passwd` 全局可写 | MEDIUM |
| IFA-BOOT-001 | boot | init.d/rcS/rc.local 中 telnetd、netcat 监听、反向 shell 等后门特征 | HIGH/MEDIUM |
| IFA-NET-001 | network | 启动脚本暴露无认证对外服务（telnetd/ftpd/nc -l） | MEDIUM |
| IFA-SSH-001 | ssh | sshd_config 弱配置（PermitRootLogin/空密码/明文密码/Protocol 1） | MEDIUM |
| IFA-FS-001 | filesystem | 对所有人可写的文件（o+w） | LOW |

## 构建

需要 gcc + CMake（Linux/WSL/macOS）。

```bash
mkdir build && cd build
cmake ..
make
# 产物: ifa (主程序), test_rules (测试)
```

无 CMake 时也可用自带的 Makefile 一键构建：

```bash
make            # 编译 ifa 和 test_rules
make test       # 跑全部单元测试 + 集成测试
make clean
```

或直接 gcc：

```bash
gcc -Wall -Wextra -g -Iinclude src/*.c -o ifa
```

## 使用

```bash
# 对一个解包好的 rootfs 做审计，文本报告输出到终端
./ifa /path/to/squashfs-root/

# 输出 JSON 报告到文件
./ifa /path/to/squashfs-root/ --json report.json

# 输出独立 HTML 报告（带统计卡片，浏览器打开）
./ifa /path/to/squashfs-root/ --html report.html

# 直接喂原始固件 .bin，自动调 binwalk 解包后再审计
./ifa --extract firmware.bin --html report.html

# 版本
./ifa --version

# 帮助
./ifa -h
```

## 演示与测试

```bash
# 生成一个"故意有漏洞"的演示 rootfs 并审计它
bash scripts/gen_demo_rootfs.sh
./ifa examples/demo_rootfs --html demo.html

# 跑全部测试（单元 25 断言 + 端到端集成）
make test
```

## 目录结构

```
├── include/            # 公共头文件（接口约定）
│   ├── audit.h         # Finding / AuditReport 数据结构
│   ├── scanner.h       # 编排器 + CliOptions
│   ├── report.h        # report_render(text/json)
│   ├── report_html.h   # HTML 报告
│   ├── extract.h       # binwalk 自动解包
│   └── rules_*.h       # 各规则模块纯函数接口
├── src/
│   ├── audit.c         # 报告数据结构操作
│   ├── report.c        # text/json 渲染
│   ├── report_html.c   # HTML 渲染
│   ├── extract.c       # binwalk 解包
│   ├── scanner.c       # 扫描编排
│   ├── cli.c           # 命令行入口
│   └── rules_*.c       # 九条规则实现
├── tests/
│   ├── test_rules.c    # 纯函数单元测试（零外部依赖）
│   └── test_integration.sh  # 端到端集成测试
├── examples/demo_rootfs     # 演示用问题固件（可重建）
├── scripts/gen_demo_rootfs.sh
├── Makefile / CMakeLists.txt
└── .github/workflows/ci.yml # GitHub Actions CI
```

## 贡献

想加规则、修 bug、改进报告？请看 [CONTRIBUTING.md](CONTRIBUTING.md)。

## ⚠️ 合规与使用红线

本工具仅用于：
- 审计厂商**公开发布**的固件更新包；
- 审计**你本人拥有或已获得书面授权**的设备；
- 教学、研究与 CTF 靶场练习。

**禁止**用于任何未授权设备的测试、渗透、数据获取。
发现问题请走负责任披露（Responsible Disclosure）流程通知厂商。

## License

MIT
