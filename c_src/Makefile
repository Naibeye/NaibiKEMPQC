# DLPL-DH PKE - C Implementation Makefile
# Optimized post-quantum public key encryption

CC ?= gcc
CFLAGS = -Wall -Wextra -Wpedantic -std=c11
LDFLAGS = -lm

# Optimization flags
OPTFLAGS = -O3 -march=native -mtune=native -ffast-math

# Debug flags
DBGFLAGS = -g -O0 -DDEBUG -fsanitize=address,undefined

# Security flags (for release)
SECFLAGS = -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE

# Source files
SRC = dlpl_ntt.c dlpl_poly.c dlpl_pke.c dlpl_kem.c
HDR = dlpl_params.h dlpl_ntt.h dlpl_poly.h dlpl_pke.h dlpl_kem.h
OBJ = $(SRC:.c=.o)

# Test programs
TEST_SRC = test_dlpl.c
TEST_OBJ = test_dlpl.o
TEST_BIN = test_dlpl

KEM_TEST_SRC = test_kem.c
KEM_TEST_OBJ = test_kem.o
KEM_TEST_BIN = test_kem

# Shared library
LIB_NAME = libdlpl_pke
STATIC_LIB = $(LIB_NAME).a
SHARED_LIB = $(LIB_NAME).so

# Default target
.PHONY: all
all: $(TEST_BIN) $(KEM_TEST_BIN)

# Release build
.PHONY: release
release: CFLAGS += $(OPTFLAGS) $(SECFLAGS)
release: clean all

# Debug build
.PHONY: debug
debug: CFLAGS += $(DBGFLAGS)
debug: LDFLAGS += -fsanitize=address,undefined
debug: clean all

# Object files
%.o: %.c $(HDR)
	$(CC) $(CFLAGS) -c $< -o $@

# Test programs
$(TEST_BIN): $(OBJ) $(TEST_OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(KEM_TEST_BIN): $(OBJ) $(KEM_TEST_OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# CAVP test vector generator
CAVP_SRC = cavp_gen.c
CAVP_OBJ = cavp_gen.o
CAVP_BIN = cavp_gen

$(CAVP_BIN): $(OBJ) $(CAVP_OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

.PHONY: cavp
cavp: CFLAGS += $(OPTFLAGS) $(SECFLAGS)
cavp: $(CAVP_BIN)
	./$(CAVP_BIN) --all --count 100

# Static library
.PHONY: static
static: $(STATIC_LIB)

$(STATIC_LIB): $(OBJ)
	ar rcs $@ $^

# Shared library
.PHONY: shared
shared: CFLAGS += -fPIC
shared: $(SHARED_LIB)

$(SHARED_LIB): $(OBJ)
	$(CC) $(CFLAGS) -shared $^ -o $@ $(LDFLAGS)

# Libraries
.PHONY: lib
lib: static shared

# Run tests
.PHONY: test
test: $(TEST_BIN) $(KEM_TEST_BIN)
	./$(TEST_BIN)
	./$(KEM_TEST_BIN)

# Run benchmarks
.PHONY: bench
bench: release
	./$(TEST_BIN) --bench
	./$(KEM_TEST_BIN) --bench

# Clean
.PHONY: clean
clean:
	rm -f $(OBJ) $(TEST_OBJ) $(KEM_TEST_OBJ) $(CAVP_OBJ) $(TEST_BIN) $(KEM_TEST_BIN) $(CAVP_BIN) $(STATIC_LIB) $(SHARED_LIB)
	rm -f *.gcda *.gcno *.gcov
	rm -f PQCkemKAT_*.rsp kat.json intermediate_values.txt

# Install (to /usr/local by default)
PREFIX ?= /usr/local
.PHONY: install
install: $(STATIC_LIB) $(SHARED_LIB)
	install -d $(PREFIX)/lib
	install -d $(PREFIX)/include/dlpl
	install -m 644 $(STATIC_LIB) $(PREFIX)/lib/
	install -m 755 $(SHARED_LIB) $(PREFIX)/lib/
	install -m 644 $(HDR) $(PREFIX)/include/dlpl/
	ldconfig || true

# Uninstall
.PHONY: uninstall
uninstall:
	rm -f $(PREFIX)/lib/$(STATIC_LIB)
	rm -f $(PREFIX)/lib/$(SHARED_LIB)
	rm -rf $(PREFIX)/include/dlpl

# Format code (requires clang-format)
.PHONY: format
format:
	clang-format -i $(SRC) $(HDR) $(TEST_SRC)

# Static analysis (requires cppcheck)
.PHONY: check
check:
	cppcheck --enable=all --suppress=missingIncludeSystem $(SRC) $(TEST_SRC)

# Code coverage (requires gcov)
.PHONY: coverage
coverage: CFLAGS += -g -O0 --coverage
coverage: LDFLAGS += --coverage
coverage: clean $(TEST_BIN)
	./$(TEST_BIN)
	gcov $(SRC)

# Documentation (requires doxygen)
.PHONY: docs
docs:
	doxygen Doxyfile 2>/dev/null || echo "Doxygen not configured"

# Different security levels
.PHONY: level1 level3 level5 toy

level1: CFLAGS += -DDLPL_SECURITY_LEVEL=1
level1: clean all

level3: CFLAGS += -DDLPL_SECURITY_LEVEL=3
level3: clean all

level5: CFLAGS += -DDLPL_SECURITY_LEVEL=5
level5: clean all

toy: CFLAGS += -DDLPL_SECURITY_LEVEL=0
toy: clean all

# Print configuration
.PHONY: info
info:
	@echo "DLPL-DH PKE C Implementation"
	@echo "============================"
	@echo "Compiler: $(CC)"
	@echo "CFLAGS:   $(CFLAGS)"
	@echo "LDFLAGS:  $(LDFLAGS)"
	@echo "Sources:  $(SRC)"
	@echo "Headers:  $(HDR)"

# Help
.PHONY: help
help:
	@echo "DLPL-DH PKE Build System"
	@echo "========================"
	@echo ""
	@echo "Targets:"
	@echo "  all       - Build test program (default)"
	@echo "  release   - Build with optimizations"
	@echo "  debug     - Build with debug symbols and sanitizers"
	@echo "  static    - Build static library"
	@echo "  shared    - Build shared library"
	@echo "  lib       - Build both libraries"
	@echo "  test      - Run test suite"
	@echo "  bench     - Run benchmarks"
	@echo "  clean     - Remove build artifacts"
	@echo "  install   - Install libraries and headers"
	@echo "  uninstall - Remove installed files"
	@echo "  format    - Format source code"
	@echo "  check     - Run static analysis"
	@echo "  coverage  - Generate code coverage report"
	@echo "  docs      - Generate documentation"
	@echo ""
	@echo "Security Levels:"
	@echo "  toy       - Toy parameters (fast, not secure)"
	@echo "  level1    - NIST Level 1 (128-bit security)"
	@echo "  level3    - NIST Level 3 (192-bit security)"
	@echo "  level5    - NIST Level 5 (256-bit security)"
	@echo ""
	@echo "Example: make release bench"
