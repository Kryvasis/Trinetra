# ─────────────────────────────────────────────────────────────
#  Iskabon — Zero-dependency C++ network scanner
#  Usage:
#    make           — build release binary
#    make debug     — build with ASAN + debug symbols
#    make install   — install to /usr/local/bin (system-wide)
#    make uninstall — remove from /usr/local/bin
#    make clean     — remove build artefacts
#    make test      — run unit tests (placeholder)
# ─────────────────────────────────────────────────────────────

CXX      := g++
STD      := -std=c++20
WARN     := -Wall -Wextra -Wpedantic -Wshadow -Wno-unused-parameter
OPT      := -O2 -march=native -flto
DBGFLAGS := -O0 -g3 -fsanitize=address,undefined
INCLUDE  := -I./include
LIBS     := -lpthread
DEFINES  :=

TARGET   := iskabon
BUILD    := build
INSTALL  := /usr/local/bin

# Collect every .cpp under src/
SRCS := $(shell find src -name '*.cpp')
OBJS := $(patsubst src/%.cpp, $(BUILD)/%.o, $(SRCS))

# ── Release ────────────────────────────────────────────────
all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(STD) $(OPT) $(WARN) $(DEFINES) -o $@ $^ $(LIBS)
	@echo "[+] Built: ./$@"

$(BUILD)/%.o: src/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(STD) $(OPT) $(WARN) $(DEFINES) $(INCLUDE) -c $< -o $@

# ── Debug / ASAN ───────────────────────────────────────────
debug: DEFINES += -DISKABON_DEBUG
debug: $(OBJS_DBG)
	$(MAKE) OPT="$(DBGFLAGS)" TARGET="$(TARGET)_debug"

# ── Install (system-wide) ──────────────────────────────────
install: all
	@echo "[*] Installing $(TARGET) to $(INSTALL)/$(TARGET)"
	install -m 755 $(TARGET) $(INSTALL)/$(TARGET)
	@echo "[+] Done. Run: iskabon --help"

uninstall:
	rm -f $(INSTALL)/$(TARGET)
	@echo "[+] Removed $(INSTALL)/$(TARGET)"

# ── Clean ─────────────────────────────────────────────────
clean:
	rm -rf $(BUILD) $(TARGET) $(TARGET)_debug
	@echo "[+] Cleaned"

# ── Tests ─────────────────────────────────────────────────
TEST_SRCS := tests/banner_probe_test.cpp tests/snmp_probe_test.cpp \
             tests/vendor_resolver_test.cpp
TEST_BINS := $(BUILD)/banner_probe_test $(BUILD)/snmp_probe_test \
             $(BUILD)/vendor_resolver_test

$(BUILD)/banner_probe_test: tests/banner_probe_test.cpp $(BUILD)/probes/banner_probe.o
	@mkdir -p $(dir $@)
	$(CXX) $(STD) $(WARN) -I./include $^ -o $@ -lpthread

$(BUILD)/snmp_probe_test: tests/snmp_probe_test.cpp $(BUILD)/probes/snmp_probe.o
	@mkdir -p $(dir $@)
	$(CXX) $(STD) $(WARN) -I./include $^ -o $@ -lpthread

$(BUILD)/vendor_resolver_test: tests/vendor_resolver_test.cpp $(BUILD)/vendor_resolver/vendor_resolver.o
	@mkdir -p $(dir $@)
	$(CXX) $(STD) $(WARN) -I./include $^ -o $@ -lpthread

test: $(TARGET) $(TEST_BINS)
	@./$(BUILD)/banner_probe_test
	@./$(BUILD)/snmp_probe_test
	@./$(BUILD)/vendor_resolver_test

.PHONY: all debug install uninstall clean test
