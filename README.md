# iot-firmware-audit (ifa)

轻量级 IoT 固件根文件系统安全审计命令行工具。
输入一个解包后的固件 rootfs（如 `squashfs-root/`），自动扫描常见安全问题并输出 text / JSON 报告。

> 设计目标：让物联网/嵌入式方向的学生在不依赖重型企业级平台的前提下，
> 用 C 完成一个真实可用的安全工具——同时作为学习 C、Linux、目录遍历、字符串处理的实战项目。

## 支持的规则

| 规则编号 | 类别 | 检测内容 |
|---|---|---|
| IFA-ACC-001/002 | account | `/etc/shadow` 弱口令哈希（MD5）、明文口令；`/etc/passwd` 错误存放哈希 |
| IFA-SEC-001 | secrets | `/etc` 下递归扫描硬编码 password/token/私钥/PSK |
| IFA-PERM-001 | suid | 整树查找 SUID/SGID 提权文件（root 属主高危） |
| IFA-BOOT-001 | boot | init.d/rcS/rc.local 中 telnetd、netcat 监听、反向 shell 等后门特征 |

## 构建

需要 gcc + CMake（Linux/WSL/macOS）。

```bash
mkdir build && cd build
cmake ..
make
# 产物: ifa (主程序), test_rules (测试)
```

无 CMake 时也可直接 gcc：

```bash
gcc -Wall -Wextra -g -Iinclude src/*.c -o ifa
```

## 使用

```bash
# 对一个解包好的 rootfs 做审计，文本报告输出到终端
./ifa /path/to/squashfs-root/

# 输出 JSON 报告到文件
./ifa /path/to/squashfs-root/ --json report.json

# 帮助
./ifa -h
```

## 跑测试

```bash
cd build && ctest --output-on-failure
# 或直接运行
./test_rules
```

## 目录结构

```
├── include/            # 公共头文件（接口约定）
│   ├── audit.h         # Finding / AuditReport 数据结构
│   ├── scanner.h       # 编排器 + CliOptions
│   ├── report.h        # report_render(text/json)
│   └── rules_*.h       # 四条规则的纯函数接口
├── src/
│   ├── audit.c         # 报告数据结构操作
│   ├── report.c        # text/json 渲染
│   ├── scanner.c       # 扫描编排
│   ├── cli.c           # 命令行入口
│   └── rules_*.c       # 四条规则实现
└── tests/test_rules.c  # 纯函数单元测试（零外部依赖）
```

## ⚠️ 合规与使用红线

本工具仅用于：
- 审计厂商**公开发布**的固件更新包；
- 审计**你本人拥有或已获得书面授权**的设备；
- 教学、研究与 CTF 靶场练习。

**禁止**用于任何未授权设备的测试、渗透、数据获取。
发现问题请走负责任披露（Responsible Disclosure）流程通知厂商。

## License

MIT
