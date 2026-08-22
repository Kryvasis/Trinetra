# ================================================================
# Trinetra Beta Makefile -- Build, lifecycle, and diagnostics
# ================================================================

# -- Configuration -----------------------------------------------
HEX_DIR       := /home/kali/.hexsrtike
API_KEY_FILE  := $(HEX_DIR)/openrouter_api_key
PID_FILE      := $(HEX_DIR)/hexstrike.pid
LOG_FILE      := $(HEX_DIR)/hexstrike.log
PORT         ?= 8888
MODEL        ?= nvidia/nemotron-3-ultra-550b-a55b:free
SRC_DIR       := src
OUT_DIR       := out

# -- Phony targets ------------------------------------------------
.PHONY: compile clean rebuild install uninstall run stop status logs test-api doctor test-gemini help test-java test-cpp test

# -- Java unit tests ----------------------------------------------
# Test classes with a main() entry point.  TrinetraChainStressWorker is
# compiled but not listed here: it is a helper spawned by the concurrency
# test, not a runnable suite.
JAVA_TEST_CLASSES := TrinetraNormalizedResultsTest TrinetraAuditTest
RUNTIME_CP        := $(CURDIR)/$(OUT_DIR):$(CURDIR)/lib/*

# ================================================================
# help -- show available targets
# ================================================================
help:
	@echo "Trinetra Beta -- Available targets:"
	@echo ""
	@echo "  make compile      Build Java classes to $(OUT_DIR)/"
	@echo "  make clean        Remove $(OUT_DIR)/ directory"
	@echo "  make rebuild      Clean + compile"
	@echo "  make install      Install 'trinetra' as global command"
	@echo "  make uninstall    Remove global 'trinetra' command"
	@echo "  make doctor       Run system diagnostics"
	@echo "  make test-gemini  Test Gemini CLI connectivity"
	@echo "  make test-api     Test OpenRouter API connectivity"
	@echo ""
	@echo "  make run          Start HexStrike server"
	@echo "  make stop         Stop HexStrike server"
	@echo "  make status       Check HexStrike server status"
	@echo "  make logs         Follow HexStrike log output"

# ================================================================
# compile -- build Trinetra from source
# ================================================================
compile:
	@mkdir -p $(OUT_DIR)
	javac -Xlint:-unchecked -d $(OUT_DIR) $(SRC_DIR)/*.java
	@echo "Build successful: $(OUT_DIR)/"

# ================================================================
# install -- install trinetra as global command (~/.local/bin)
# ================================================================
install: compile
	@chmod +x $(CURDIR)/trinetra
	@mkdir -p $(HOME)/.local/bin
	@cp $(CURDIR)/trinetra $(HOME)/.local/bin/trinetra
	@chmod +x $(HOME)/.local/bin/trinetra
	@echo "Installed: ~/.local/bin/trinetra"
	@echo "You can now run: trinetra -help"

# ================================================================
# uninstall -- remove global trinetra command
# ================================================================
uninstall:
	@rm -f $(HOME)/.local/bin/trinetra
	@echo "Removed: ~/.local/bin/trinetra"

# ================================================================
# clean -- remove compiled classes
# ================================================================
clean:
	rm -rf $(OUT_DIR)
	@echo "Cleaned $(OUT_DIR)/"

# ================================================================
# rebuild -- clean + compile
# ================================================================
rebuild: clean compile

# ================================================================
# test-java -- compile tests/*.java against out/ and run each suite
# Each suite runs against a throwaway -Dtrinetra.root temp dir so
# real sessions/ are never touched.  Fails if any suite exits != 0.
# ================================================================
test-java: compile
	javac -cp $(OUT_DIR) -d $(OUT_DIR) tests/*.java
	@rc=0; \
	for cls in $(JAVA_TEST_CLASSES); do \
		root=$$(mktemp -d /tmp/trinetra_test_XXXXXX); \
		echo "[$$cls]"; \
		java -Dtrinetra.root="$$root" -cp "$(RUNTIME_CP)" $$cls || rc=1; \
		rm -rf "$$root"; \
	done; \
	if [ $$rc -eq 0 ]; then echo "[+] test-java: all suites passed"; \
	else echo "[-] test-java: FAILURE(S)"; fi; \
	exit $$rc

# ================================================================
# test-cpp -- run Iskabon's C++ unit suites (own Makefile)
# ================================================================
test-cpp:
	@$(MAKE) --no-print-directory -C Iskabon test

# ================================================================
# test -- combined: Java + C++ suites
# ================================================================
test: test-java test-cpp

# ================================================================
# doctor -- run system diagnostics via Trinetra
# ================================================================
doctor: compile
	@java -Dtrinetra.root=$(CURDIR) -cp $(OUT_DIR) Trinetra -doctor

# ================================================================
# test-gemini -- verify Gemini CLI is working
# ================================================================
test-gemini:
	@echo "Testing Gemini CLI..."
	@GEMINI_API_KEY=$$(python3 -c "import json; print(json.load(open('$(HOME)/.gemini/settings.json'))['apiKey'])" 2>/dev/null); \
	if [ -z "$$GEMINI_API_KEY" ]; then \
		echo "ERROR: No Gemini API key found in ~/.gemini/settings.json"; \
		exit 1; \
	fi; \
	echo "API key: found"; \
	GEMINI_API_KEY="$$GEMINI_API_KEY" ~/.npm-global/bin/gemini -m gemini-2.5-flash-lite -p "say OK" --yolo --skip-trust 2>&1 | \
		grep -v "YOLO mode" | grep -v "Ripgrep" | grep -v "Approval mode" || echo "ERROR: Gemini CLI failed"

# ================================================================
# run -- start hexstrike_server in background
# ================================================================
run:
	@mkdir -p "$(HEX_DIR)"
	@test -f "$(API_KEY_FILE)" || \
		{ echo "ERROR: API key file not found: $(API_KEY_FILE)"; exit 1; }
	@test -s "$(API_KEY_FILE)" || \
		{ echo "ERROR: API key file is empty: $(API_KEY_FILE)"; exit 1; }
	@if [ -f "$(PID_FILE)" ]; then \
		OLD_PID=$$(cat "$(PID_FILE)"); \
		if kill -0 "$$OLD_PID" 2>/dev/null; then \
			echo "ERROR: HexStrike already running (PID $$OLD_PID). Use 'make stop' first."; \
			exit 1; \
		else \
			rm -f "$(PID_FILE)"; \
		fi; \
	fi
	@echo "Starting HexStrike on port $(PORT)..."
	@hexstrike_server --port "$(PORT)" > "$(LOG_FILE)" 2>&1 & \
		echo $$! > "$(PID_FILE)"; \
	NEW_PID=$$(cat "$(PID_FILE)"); \
		echo "HexStrike started (PID $$NEW_PID, log: $(LOG_FILE))"

# ================================================================
# stop -- gracefully stop hexstrike_server
# ================================================================
stop:
	@if [ ! -f "$(PID_FILE)" ]; then \
		echo "HexStrike is not running."; \
		exit 0; \
	fi
	@PID=$$(cat "$(PID_FILE)"); \
	if kill -0 "$$PID" 2>/dev/null; then \
		echo "Stopping HexStrike (PID $$PID)..."; \
		kill "$$PID"; \
		echo "HexStrike stopped."; \
	else \
		echo "HexStrike is not running (stale PID)."; \
	fi; \
	rm -f "$(PID_FILE)"

# ================================================================
# status -- report whether hexstrike_server is running
# ================================================================
status:
	@if [ ! -f "$(PID_FILE)" ]; then \
		echo "HexStrike is NOT running (no PID file)."; \
		exit 0; \
	fi
	@PID=$$(cat "$(PID_FILE)"); \
	if kill -0 "$$PID" 2>/dev/null; then \
		echo "HexStrike is running (PID $$PID, port $(PORT))."; \
	else \
		echo "HexStrike is NOT running (stale PID $$PID)."; \
		exit 1; \
	fi

# ================================================================
# logs -- follow hexstrike log output
# ================================================================
logs:
	@test -f "$(LOG_FILE)" || \
		{ echo "ERROR: Log file not found: $(LOG_FILE)"; exit 1; }
	@tail -f "$(LOG_FILE)"

# ================================================================
# test-api -- send a test request to OpenRouter
# ================================================================
test-api:
	@test -f "$(API_KEY_FILE)" || \
		{ echo "ERROR: API key file not found: $(API_KEY_FILE)"; exit 1; }
	@test -s "$(API_KEY_FILE)" || \
		{ echo "ERROR: API key file is empty: $(API_KEY_FILE)"; exit 1; }
	@OPENROUTER_API_KEY=$$(cat "$(API_KEY_FILE)" | tr -d '[:space:]'); \
	if [ -z "$$OPENROUTER_API_KEY" ]; then \
		echo "ERROR: API key is blank after trimming."; \
		exit 1; \
	fi; \
	echo "Testing OpenRouter API with model $(MODEL)..."; \
	echo ""; \
	curl -s -w "\n---\nHTTP Status: %{http_code}\n" \
		-X POST "https://openrouter.ai/api/v1/chat/completions" \
		-H "Authorization: Bearer $$OPENROUTER_API_KEY" \
		-H "Content-Type: application/json" \
		-d '{"model":"$(MODEL)","messages":[{"role":"user","content":"ping"}],"max_tokens":10}' | \
	jq . 2>/dev/null || cat; \
	echo ""
