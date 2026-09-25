cmake_minimum_required(VERSION 3.16)
project(iot_firmware_audit C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Wextra -g -Wno-format-truncation)
include_directories(${CMAKE_SOURCE_DIR}/include)

# 规则模块（新增规则在 registry.c 的 RULES[] 表里登记，并把 .c 加到这里）
set(RULES_SOURCES
    src/rules_account.c
    src/rules_secrets.c
    src/rules_suid.c
    src/rules_boot.c
    src/rules_net.c
    src/rules_worldwritable.c
    src/rules_ssh.c
    src/rules_perms.c
    src/rules_web.c
    src/rules_crack.c
)

# 主程序
add_executable(ifa
    src/audit.c
    src/report.c
    src/report_html.c
    src/remediation.c
    ${RULES_SOURCES}
    src/registry.c
    src/extract.c
    src/scanner.c
    src/cli.c
)
target_link_libraries(ifa crypt)

# 测试程序
enable_testing()
add_executable(test_rules
    tests/test_rules.c
    src/audit.c
    src/remediation.c
    ${RULES_SOURCES}
)
target_include_directories(test_rules PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(test_rules crypt)
add_test(NAME rules_test COMMAND test_rules)
