# ================================================================
# Trinetra Beta Makefile -- Build, lifecycle, and diagnostics
# ================================================================

# -- Configuration -----------------------------------------------
SRC_DIR       := src
OUT_DIR       := out

# -- Phony targets ------------------------------------------------
.PHONY: compile clean rebuild install uninstall doctor test-gemini help test-java test-cpp test

# -- Java unit tests ----------------------------------------------
# Test classes with a main() entry point.  TrinetraChainStressWorker is
# compiled but not listed here: it is a helper spawned by the concurrency
# test, not a runnable suite.
JAVA_TEST_CLASSES := TrinetraNormalizedResultsTest TrinetraAuditTest \
                     TrinetraTestSelectionTest TrinetraVendorConnectorTest \
                     TrinetraComplianceTest TrinetraStatNormalizedResultsTest \
                     TrinetraComplianceScorerTest TrinetraNarrativeGeneratorTest \
                     TrinetraAuditReportBuilderTest
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
	@echo ""

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

