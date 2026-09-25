cmake_minimum_required(VERSION 3.16)
project(iot_firmware_audit C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Wextra -g -Wno-format-truncation)
include_directories(${CMAKE_SOURCE_DIR}/include)

# 规则模块（新增规则在这里登记，scanner.c 里也调用一下即可）
set(RULES_SOURCES
    src/rules_account.c
    src/rules_secrets.c
    src/rules_suid.c
    src/rules_boot.c
    src/rules_net.c
    src/rules_worldwritable.c
    src/rules_ssh.c
    src/rules_perms.c
)

# 主程序
add_executable(ifa
    src/audit.c
    src/report.c
    src/report_html.c
    ${RULES_SOURCES}
    src/extract.c
    src/scanner.c
    src/cli.c
)

# 测试程序
enable_testing()
add_executable(test_rules
    tests/test_rules.c
    src/audit.c
    ${RULES_SOURCES}
)
target_include_directories(test_rules PRIVATE ${CMAKE_SOURCE_DIR}/include)
add_test(NAME rules_test COMMAND test_rules)
