# iot-firmware-audit — 一键构建（无 CMake 时用）
CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -g -Wno-format-truncation -Iinclude
LDLIBS  := -lcrypt
SRCS    := src/audit.c src/report.c src/report_html.c src/report_sarif.c src/remediation.c \
           src/rules_account.c src/rules_secrets.c src/rules_suid.c src/rules_boot.c \
           src/rules_net.c src/rules_worldwritable.c src/rules_ssh.c src/rules_perms.c \
           src/rules_web.c src/rules_crack.c src/rules_components.c \
           src/registry.c src/extract.c src/scanner.c src/cli.c
TEST_SRCS := tests/test_rules.c src/audit.c src/remediation.c \
           src/rules_account.c src/rules_secrets.c src/rules_suid.c src/rules_boot.c \
           src/rules_net.c src/rules_worldwritable.c src/rules_ssh.c src/rules_perms.c \
           src/rules_crack.c src/rules_components.c

all: ifa test_rules

ifa: $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o ifa $(LDLIBS)

test_rules: $(TEST_SRCS)
	$(CC) $(CFLAGS) $(TEST_SRCS) -o test_rules $(LDLIBS)

test: test_rules
	./test_rules
	bash tests/test_integration.sh

integration: ifa
	bash tests/test_integration.sh

clean:
	rm -f ifa test_rules

.PHONY: all test integration clean
