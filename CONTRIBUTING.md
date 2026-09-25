# Contributing

感谢你愿意为 iot-firmware-audit 贡献代码。这个项目是新手友好的，欢迎任何水平的 PR。

## 新增一条规则（最推荐的入门贡献）

1. 在 `include/` 新建 `rules_<name>.h`，声明：
   - 一个**纯判定函数**（输入一行/一个 mode，输出是否命中 + Finding），方便单测；
   - 一个扫描入口 `int audit_<name>(AuditReport *rep, const char *root)`。
2. 在 `src/` 新建 `rules_<name>.c` 实现（参考 `rules_account.c` 的写法）。
3. 在 `src/scanner.c` 里调用新规则（和 `audit_suid_tree` 等并列）。
4. 在 `tests/test_rules.c` 里加对应断言（`test_<name>()`）。
5. 在 `CMakeLists.txt` 和 `Makefile` 的 `RULES_SOURCES` / `SRCS` 中登记。
6. 在 `README.md` 规则表中加一行。
7. 本地验证：`make test` 全过。

## 代码约定

- 纯 C99，不引入外部库（唯一可选依赖是 binwalk，且只在 `--extract` 用到）。
- 判定逻辑写成纯函数，禁止在判定函数里访问文件系统。
- 字符串用 `snprintf` 并显式传缓冲区大小；路径缓冲区不小于 2048。
- 所有输出文本中英文皆可，但字段、规则编号、JSON 键保持英文。
- 错误处理：文件打不开不视为失败，静默跳过即可（很多 rootfs 没有该文件）。

## 规则编号

`IFA-<类别>-<序号>`，如 `IFA-ACC-001`。类别见 README 规则表。

## 提交规范

- 提交信息：`feat: ...` / `fix: ...` / `docs: ...` / `test: ...`。
- 一个 PR 只做一件事。
- 先跑 `make test`，再提交。

## 合规

本项目仅用于授权/公开固件审计。请勿提交任何针对未授权设备的功能或绕过手段。
