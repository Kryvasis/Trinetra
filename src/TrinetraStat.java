import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.*;

/**
 * Static test execution layer — trinetra_stat.java
 * Loads 2_static_map.json and 3_decision_engine.csv as authoritative source.
 * Executes stat_scripts/<code>.sh, applies decision rules, writes to session.json.
 *
 * Commands:
 *   statRun(code, session, target)     -> run single stat_script + evaluate
 *   statRunAll(session, target)        -> run all stat-owned tests sequentially
 *   statStatus(session)                -> print pass/fail/review tally
 */
public class TrinetraStat {

    public static final Path STAT_SCRIPTS_DIR = Path.of(TrinetraCommon.PROJECT_ROOT, "stat_scripts");

    // ── Verdict enum ──
    public enum Verdict {
        PASS, FAIL, MANUAL_REVIEW, ERROR
    }

    // ── Inner class: DecisionRule ──
    public static class DecisionRule {
        public final String evalMethod;
        public final String passCriteria;
        public final String failCriteria;
        public final String fallbackMethod;

        public DecisionRule(String evalMethod, String passCriteria, String failCriteria, String fallbackMethod) {
            this.evalMethod = evalMethod;
            this.passCriteria = passCriteria;
            this.failCriteria = failCriteria;
            this.fallbackMethod = fallbackMethod;
        }
    }

    // ── Inner class: TestDefinition ──
    public static class TestDefinition {
        public final String code;
        public final String name;
        public final String category;
        public final String tool;
        public final String script;
        public final DecisionRule decisionRule;
        public final String defaultSeverity;

        public TestDefinition(String code, String name, String category, String tool,
                              String script, DecisionRule decisionRule, String defaultSeverity) {
            this.code = code;
            this.name = name;
            this.category = category;
            this.tool = tool;
            this.script = script;
            this.decisionRule = decisionRule;
            this.defaultSeverity = defaultSeverity;
        }
    }

    // ── State: loaded test definitions ──
    static Map<String, TestDefinition> testDefinitions = new LinkedHashMap<>();

    public static TestDefinition getTestDefinition(String code) {
        loadDefinitions();
        return testDefinitions.get(code.toUpperCase());
    }

    // ── Load static map and decision engine ──
    @SuppressWarnings("unchecked")
    public static synchronized void loadDefinitions() {
        if (!testDefinitions.isEmpty()) return;

        // Load from 2_static_map.json
        Path staticMapPath = Path.of(TrinetraCommon.PROJECT_ROOT, "2_static_map.json");
        String staticMapContent = TrinetraCommon.readFile(staticMapPath);
        if (staticMapContent != null) {
            Object parsed = TrinetraJson.parse(staticMapContent);
            if (parsed instanceof Map) {
                Map<String, Object> map = (Map<String, Object>) parsed;
                for (Map.Entry<String, Object> entry : map.entrySet()) {
                    String code = entry.getKey();
                    if (!(entry.getValue() instanceof Map)) continue;
                    Map<String, Object> def = (Map<String, Object>) entry.getValue();

                    String name = TrinetraCommon.getString(def, "name", "");
                    String category = TrinetraCommon.getString(def, "category", "");
                    String tool = TrinetraCommon.getString(def, "tool", "");
                    String script = TrinetraCommon.getString(def, "script", code + ".sh");
                    String severity = TrinetraCommon.getString(def, "default_severity", "Low");

                    DecisionRule rule = null;
                    Object drObj = def.get("decision_rule");
                    if (drObj instanceof Map) {
                        Map<String, Object> dr = (Map<String, Object>) drObj;
                        rule = new DecisionRule(
                            TrinetraCommon.getString(dr, "method", "manual_review_required"),
                            TrinetraCommon.getString(dr, "pass_criteria", ""),
                            TrinetraCommon.getString(dr, "fail_criteria", ""),
                            "manual_review_required"
                        );
                    }

                    testDefinitions.put(code, new TestDefinition(
                        code, name, category, tool, script, rule, severity));
                }
            }
        }

        // Enrich from 3_decision_engine.csv (overrides fallback_method and adds eval details)
        Path decisionPath = Path.of(TrinetraCommon.PROJECT_ROOT, "3_decision_engine.csv");
        String csvContent = TrinetraCommon.readFile(decisionPath);
        if (csvContent != null) {
            String[] lines = csvContent.split("\n");
            if (lines.length > 1) {
                // Skip header
                for (int i = 1; i < lines.length; i++) {
                    String line = lines[i].trim();
                    if (line.isEmpty()) continue;
                    String[] parts = parseCsvLine(line);
                    if (parts.length < 11) continue;

                    String code = parts[0].trim();
                    String name = parts[1].trim();
                    String category = parts[2].trim();
                    String tool = parts[3].trim();
                    String scriptFile = parts[4].trim();
                    String evalMethod = parts[5].trim();
                    String passCriteria = parts[6].trim();
                    String failCriteria = parts[7].trim();
                    String severity = parts[8].trim();
                    String fallbackMethod = parts[9].trim();

                    DecisionRule rule = new DecisionRule(evalMethod, passCriteria, failCriteria, fallbackMethod);

                    if (testDefinitions.containsKey(code)) {
                        // Update existing definition with CSV data
                        TestDefinition existing = testDefinitions.get(code);
                        testDefinitions.put(code, new TestDefinition(
                            code, name.isEmpty() ? existing.name : name,
                            category.isEmpty() ? existing.category : category,
                            tool.isEmpty() ? existing.tool : tool,
                            scriptFile.isEmpty() ? existing.script : scriptFile,
                            rule,
                            severity.isEmpty() ? existing.defaultSeverity : severity));
                    } else {
                        testDefinitions.put(code, new TestDefinition(
                            code, name, category, tool, scriptFile, rule, severity));
                    }
                }
            }
        }

        TrinetraCommon.logInfo("Loaded " + testDefinitions.size() + " test definitions from static_map + decision_engine");
    }

    private static String[] parseCsvLine(String line) {
        List<String> parts = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean inQuotes = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '"') {
                inQuotes = !inQuotes;
            } else if (c == ',' && !inQuotes) {
                parts.add(current.toString());
                current = new StringBuilder();
            } else {
                current.append(c);
            }
        }
        parts.add(current.toString());
        return parts.toArray(new String[0]);
    }

    // ── DecisionEngine: pure, stateless evaluation ──
    public static class DecisionEngine {
        /**
         * Evaluate raw script output against a decision rule.
         * Returns a Verdict: PASS, FAIL, MANUAL_REVIEW, or ERROR.
         * Canonical contract: if stdout contains a line "VERDICT: <pass|fail|manual_review|error>"
         * (case-insensitive, last occurrence wins), that verdict is authoritative and
         * exit code is treated as execution signal only. Otherwise falls back to
         * legacy grep/exit_code methods for backward compatibility.
         */
        public static Verdict evaluate(DecisionRule rule, String rawOutput, int exitCode) {
            // New canonical path: explicit VERDICT line takes precedence
            Verdict explicit = parseExplicitVerdict(rawOutput);
            if (explicit != null) {
                return explicit;
            }
            // If script signaled execution failure via non-zero exit and produced no output, treat as ERROR
            // (legacy scripts that conflate exit code with verdict will still be handled below)
            if (rule == null) {
                return Verdict.MANUAL_REVIEW;
            }

            String method = rule.evalMethod;
            if (method == null || method.isEmpty()) {
                return Verdict.MANUAL_REVIEW;
            }

            try {
                switch (method) {
                    case "grep_present":
                        return evalGrepPresent(rule, rawOutput);
                    case "grep_absent":
                        return evalGrepAbsent(rule, rawOutput);
                    case "exit_code_zero":
                        return evalExitCode(rule, rawOutput, exitCode);
                    case "numeric_threshold":
                        return evalNumericThreshold(rule, rawOutput);
                    case "regex_match":
                        return evalRegexMatch(rule, rawOutput);
                    default:
                        TrinetraCommon.logWarn("Unknown eval method: " + method);
                        return Verdict.MANUAL_REVIEW;
                }
            } catch (Exception e) {
                TrinetraCommon.logError("Decision engine error for " + method + ": " + e.getMessage());
                return Verdict.ERROR;
            }
        }

        /** Parse explicit VERDICT line from script output, if present. */
        private static Verdict parseExplicitVerdict(String rawOutput) {
            if (rawOutput == null || rawOutput.isBlank()) return null;
            // Find last occurrence of VERDICT: <value> (case-insensitive)
            String lower = rawOutput.toLowerCase();
            // Use regex to find all verdict lines
            java.util.regex.Pattern p = java.util.regex.Pattern.compile(
                "^\\s*verdict\\s*:\\s*(pass|fail|manual_review|error)\\s*$",
                java.util.regex.Pattern.CASE_INSENSITIVE | java.util.regex.Pattern.MULTILINE);
            java.util.regex.Matcher m = p.matcher(rawOutput);
            String last = null;
            while (m.find()) {
                last = m.group(1).toLowerCase();
            }
            if (last == null) return null;
            switch (last) {
                case "pass": return Verdict.PASS;
                case "fail": return Verdict.FAIL;
                case "manual_review": return Verdict.MANUAL_REVIEW;
                case "error": return Verdict.ERROR;
                default: return null;
            }
        }

        private static Verdict evalGrepPresent(DecisionRule rule, String rawOutput) {
            if (rawOutput == null || rawOutput.isBlank()) {
                return Verdict.MANUAL_REVIEW;
            }
            String lower = rawOutput.toLowerCase();

            // Check fail criteria first (fail takes precedence to avoid false negatives)
            if (!rule.failCriteria.isEmpty() && matchesCriteria(lower, rule.failCriteria)) {
                return Verdict.FAIL;
            }
            // Then check pass criteria
            if (!rule.passCriteria.isEmpty() && matchesCriteria(lower, rule.passCriteria)) {
                return Verdict.PASS;
            }

            // For grep_present: if the expected "pass" indicator is absent, that may be a fail
            // But we can't be sure without clearer criteria, so manual review
            return Verdict.MANUAL_REVIEW;
        }

        private static Verdict evalGrepAbsent(DecisionRule rule, String rawOutput) {
            if (rawOutput == null || rawOutput.isBlank()) {
                // Empty output means nothing bad found → pass for grep_absent
                return Verdict.PASS;
            }
            String lower = rawOutput.toLowerCase();

            // Check fail criteria first
            if (!rule.failCriteria.isEmpty() && matchesCriteria(lower, rule.failCriteria)) {
                return Verdict.FAIL;
            }
            // Check pass criteria
            if (!rule.passCriteria.isEmpty() && matchesCriteria(lower, rule.passCriteria)) {
                return Verdict.PASS;
            }

            return Verdict.MANUAL_REVIEW;
        }

        private static Verdict evalExitCode(DecisionRule rule, String rawOutput, int exitCode) {
            // Primary signal: exit code
            if (exitCode == 0) {
                return Verdict.PASS;
            } else if (exitCode > 0) {
                // Non-zero exit code might indicate failure or findings
                // Cross-check with text criteria if present
                if (rawOutput != null) {
                    String lower = rawOutput.toLowerCase();
                    if (!rule.failCriteria.isEmpty() && matchesCriteria(lower, rule.failCriteria)) {
                        return Verdict.FAIL;
                    }
                    if (!rule.passCriteria.isEmpty() && matchesCriteria(lower, rule.passCriteria)) {
                        return Verdict.PASS;
                    }
                }
                return Verdict.MANUAL_REVIEW;
            }
            return Verdict.ERROR;
        }

        private static Verdict evalNumericThreshold(DecisionRule rule, String rawOutput) {
            if (rawOutput == null || rawOutput.isBlank()) {
                return Verdict.MANUAL_REVIEW;
            }

            // Try to extract a numeric value from output
            // Look for common patterns: "response time: 1.23s", "entropy: 128.5 bits", etc.
            double value = Double.NaN;

            // Try to find a decimal number with optional unit
            Pattern numPattern = Pattern.compile("(\\d+\\.\\d+)\\s*(s|ms|bits|bytes|sec|seconds)?");
            Matcher m = numPattern.matcher(rawOutput);
            if (m.find()) {
                try {
                    value = Double.parseDouble(m.group(1));
                    String unit = m.group(2);
                    // Convert ms to s if needed
                    if ("ms".equals(unit)) {
                        value = value / 1000.0;
                    }
                } catch (NumberFormatException e) {
                    // ignore
                }
            }

            if (Double.isNaN(value)) {
                return Verdict.MANUAL_REVIEW;
            }

            // Determine threshold from criteria
            // pass_criteria like "response time < 2s" or "entropy >= 128 bits"
            // fail_criteria like "catastrophic backtracking (>10s)" or "low-entropy/predictable token"

            // Simple heuristic: try to extract threshold numbers from criteria
            double passThreshold = extractThreshold(rule.passCriteria);
            double failThreshold = extractThreshold(rule.failCriteria);

            if (!Double.isNaN(failThreshold) && value >= failThreshold) {
                return Verdict.FAIL;
            }
            if (!Double.isNaN(passThreshold) && value < passThreshold) {
                return Verdict.PASS;
            }

            // If we have a pass threshold and value is below it, pass
            if (!Double.isNaN(passThreshold) && value <= passThreshold) {
                return Verdict.PASS;
            }

            return Verdict.MANUAL_REVIEW;
        }

        private static Verdict evalRegexMatch(DecisionRule rule, String rawOutput) {
            if (rawOutput == null || rawOutput.isBlank()) {
                return Verdict.MANUAL_REVIEW;
            }

            // Use fail_criteria as a regex pattern
            if (!rule.failCriteria.isEmpty()) {
                try {
                    if (Pattern.compile(rule.failCriteria, Pattern.CASE_INSENSITIVE).matcher(rawOutput).find()) {
                        return Verdict.FAIL;
                    }
                } catch (PatternSyntaxException e) {
                    // Fall back to plain text search
                    if (rawOutput.toLowerCase().contains(rule.failCriteria.toLowerCase())) {
                        return Verdict.FAIL;
                    }
                }
            }

            if (!rule.passCriteria.isEmpty()) {
                try {
                    if (Pattern.compile(rule.passCriteria, Pattern.CASE_INSENSITIVE).matcher(rawOutput).find()) {
                        return Verdict.PASS;
                    }
                } catch (PatternSyntaxException e) {
                    if (rawOutput.toLowerCase().contains(rule.passCriteria.toLowerCase())) {
                        return Verdict.PASS;
                    }
                }
            }

            return Verdict.MANUAL_REVIEW;
        }

        private static boolean matchesCriteria(String lowerOutput, String criteria) {
            if (criteria.isEmpty()) return false;
            String lowerCriteria = criteria.toLowerCase();

            // Split on "," for multiple alternative patterns
            String[] patterns = lowerCriteria.split("\\s*,\\s*");
            for (String pat : patterns) {
                pat = pat.trim();
                if (pat.isEmpty()) continue;
                // Handle "no X" patterns as presence checks
                if (pat.startsWith("no ")) {
                    // "no email/creds found" means absence is pass
                    String absencePat = pat.substring(3).trim();
                    // If the negative indicator is NOT in output, this matches
                    if (!lowerOutput.contains(absencePat.replace("/", " "))) {
                        return true;
                    }
                } else {
                    if (lowerOutput.contains(pat)) {
                        return true;
                    }
                }
            }
            return false;
        }

        private static double extractThreshold(String criteria) {
            if (criteria == null || criteria.isEmpty()) return Double.NaN;
            // Look for numbers in criteria: "< 2s", ">= 128 bits", ">10s"
            Pattern p = Pattern.compile("[<>=]+\\s*(\\d+\\.?\\d*)");
            Matcher m = p.matcher(criteria);
            if (m.find()) {
                try {
                    return Double.parseDouble(m.group(1));
                } catch (NumberFormatException e) {
                    return Double.NaN;
                }
            }
            return Double.NaN;
        }
    }

    // ── Execute a single stat test ──
    public static Map<String, Object> statRun(String code, String sessionName, String target) {
        return statRun(code, sessionName, target, null);
    }

    /** statRun with optional extra environment (vendor connector vars). */
    public static Map<String, Object> statRun(String code, String sessionName,
                                              String target,
                                              Map<String, String> extraEnv) {
        loadDefinitions();

        String sanitized = TrinetraCommon.sanitizeName(sessionName);
        code = code.toUpperCase();

        TestDefinition testDef = testDefinitions.get(code);
        if (testDef == null) {
            TrinetraCommon.logError("Unknown test code: " + code);
            return buildStatFailure(code, target, "Unknown test code: " + code);
        }

        // Ensure session exists
        Map<String, Object> session = TrinetraSession.loadSession(sanitized);
        if (session == null) {
            TrinetraCommon.logInfo("Auto-creating session: " + sanitized);
            session = TrinetraSession.createSession(sanitized, target);
            if (session == null) {
                return buildStatFailure(code, target, "Failed to create session: " + sanitized);
            }
        }

        // Resolve script path
        Path scriptPath = STAT_SCRIPTS_DIR.resolve(code + ".sh");
        if (!Files.exists(scriptPath)) {
            TrinetraCommon.logError("Stat script not found: " + scriptPath);
            return buildStatFailure(code, target, "Stat script not found: " + code + ".sh");
        }

        int beforeCount = countFindings(sanitized);

        TrinetraCommon.logInfo("Running stat test " + code + " (" + testDef.name + ") against " + target);
        TrinetraCommon.sessionLog(sanitized, code, "STAT_START " + code + " (" + testDef.name + ")");

        // Execute the stat script
        // Script contract: bash stat_scripts/<code>.sh <target> <session_output_dir>
        // Vendor connector context is injected via environment (Prompt 13).
        // Multi-vendor: resolve effective vendor per device (device_vendors map
        // takes precedence over session-level vendor_resolution) and stamp
        // both the executed script env and the persisted normalized_results
        // with that device's vendor, preventing cross-vendor leakage.
        String effectiveVendorRaw = null;
        if (extraEnv != null && extraEnv.containsKey("TRINETRA_VENDOR")) {
            effectiveVendorRaw = extraEnv.get("TRINETRA_VENDOR");
        }
        if (effectiveVendorRaw == null || effectiveVendorRaw.isBlank()) {
            effectiveVendorRaw = TrinetraSession.getEffectiveVendorForDevice(sanitized, target);
        }
        if (effectiveVendorRaw == null || effectiveVendorRaw.isBlank()) {
            effectiveVendorRaw = TrinetraSession.getSessionFinalVendor(sanitized);
        }
        VendorConnector effectiveConnector = VendorConnectorRegistry.resolve(effectiveVendorRaw);
        String effectiveVendorCanon = effectiveConnector.getVendorName();
        // Decide which env to actually exec with: merge caller-provided env
        // but guarantee correct per-device vendor is what the script sees.
        Map<String, String> execEnv = extraEnv;
        if (execEnv == null) {
            execEnv = new HashMap<>();
        } else {
            // copy to avoid mutating caller's map when we enforce canonical
            execEnv = new HashMap<>(execEnv);
        }
        // Canonical vendor is what the script should see; raw requested kept for audit.
        execEnv.put("TRINETRA_VENDOR", effectiveVendorCanon);
        execEnv.put("TRINETRA_VENDOR_REQUESTED", effectiveVendorRaw);
        execEnv.putIfAbsent("TRINETRA_CONNECTOR", effectiveConnector.getClass().getSimpleName());
        // For per-device auto-connect tracking (single statRun, no batch lifecycle)
        boolean autoConnected = false;
        if (extraEnv == null) {
            try { effectiveConnector.connect(target, new HashMap<>()); autoConnected = true; } catch (Exception ignored) {}
        }
        String sessionOutDir = TrinetraCommon.sessionDir(sanitized).toString();
        String[] result = TrinetraCommon.execCommand(300, execEnv,
            "bash", scriptPath.toString(), target, sessionOutDir);
        String stdout = result[0];
        String stderr = result[1];
        int exitCode;
        try { exitCode = Integer.parseInt(result[2]); } catch (Exception e) { exitCode = -1; }

        // Save raw output
        Path rawOutputPath = TrinetraCommon.sessionDir(sanitized).resolve(code + "_static_raw.txt");
        StringBuilder rawContent = new StringBuilder();
        rawContent.append("=== ").append(code).append(" ===\n");
        rawContent.append("Target: ").append(target).append("\n");
        rawContent.append("Exit code: ").append(exitCode).append("\n");
        rawContent.append("=== STDOUT ===\n").append(stdout).append("\n");
        rawContent.append("=== STDERR ===\n").append(stderr).append("\n");
        TrinetraCommon.atomicWriteFile(rawOutputPath, rawContent.toString());

        // Apply decision engine
        Verdict verdict = Verdict.MANUAL_REVIEW;
        String verdictDetail = "";
        if (testDef.decisionRule != null) {
            verdict = DecisionEngine.evaluate(testDef.decisionRule, stdout, exitCode);
            verdictDetail = testDef.decisionRule.evalMethod + " -> " + verdict;
        } else {
            verdictDetail = "No decision rule defined -> MANUAL_REVIEW";
        }

        if (verdict == Verdict.MANUAL_REVIEW) {
            TrinetraCommon.logWarn(code + " -> MANUAL_REVIEW: " + verdictDetail);
            TrinetraCommon.sessionLog(sanitized, code, "FALLBACK manual_review: " + verdictDetail);
        }

        // Build finding record
        Map<String, Object> finding = TrinetraCommon.newMap();
        finding.put("finding_id", UUID.randomUUID().toString());
        finding.put("v_code", code);
        finding.put("test_code", code);
        finding.put("v_name", testDef.name);
        finding.put("target", target);
        finding.put("script", "stat_scripts/" + code + ".sh");
        finding.put("started_at", TrinetraCommon.nowIso());
        finding.put("ended_at", TrinetraCommon.nowIso());
        finding.put("exit_code", exitCode);
        finding.put("verdict", verdict.name().toLowerCase());
        finding.put("verdict_detail", verdictDetail);
        finding.put("eval_method", testDef.decisionRule != null ? testDef.decisionRule.evalMethod : "none");
        finding.put("pass_criteria", testDef.decisionRule != null ? testDef.decisionRule.passCriteria : "");
        finding.put("fail_criteria", testDef.decisionRule != null ? testDef.decisionRule.failCriteria : "");
        finding.put("default_severity", testDef.defaultSeverity);
        finding.put("category", testDef.category);
        finding.put("tool", testDef.tool);

        boolean success = verdict == Verdict.PASS;
        finding.put("success", success);
        finding.put("status", success ? "pass" : verdict.name().toLowerCase());
        finding.put("raw_output", stdout);
        finding.put("raw_stderr", stderr);
        finding.put("stdout", stdout);
        finding.put("stderr", stderr);
        finding.put("summary", verdictDetail);
        finding.put("summary_status", "captured_but_unsummarized");
        finding.put("artifacts", TrinetraCommon.newList());
        finding.put("tags", TrinetraCommon.newList());
        finding.put("engine", "trinetra_stat");

        // Append to session JSON (same file used by trinetra_pen)
        boolean appended = TrinetraSession.appendFinding(sanitized, finding);

        if (appended) {
            TrinetraCommon.logInfo(code + " -> " + verdict.name() + " (appended to session)");
            TrinetraCommon.sessionLog(sanitized, code, "STAT_DONE verdict=" + verdict.name());

            // Append to normalized_results (tamper-evident chain, Prompt 8-10).
            // This is additive — findings are already written above; this
            // populates the second field so chain_hash / verifyChain()
            // are maintained during real CLI runs, not just unit tests.
            // Use the same per-device effective vendor that was injected
            // into the script env, to prevent cross-vendor leakage.
            String vendor = effectiveVendorRaw;
            // Fallback if somehow not set (should not happen)
            if (vendor == null || vendor.isBlank()) {
                vendor = TrinetraSession.getEffectiveVendorForDevice(sanitized, target);
            }
            Map<String, Object> normalizedEntry = TrinetraCommon.newMap();
            normalizedEntry.put("device_id", target);
            normalizedEntry.put("vendor", vendor);
            normalizedEntry.put("test_id", code);
            normalizedEntry.put("raw_output", stdout);
            normalizedEntry.put("normalized_result", verdict.name().toLowerCase());
            // timestamp auto-filled by appendNormalizedResult
            TrinetraSession.appendNormalizedResult(sanitized, normalizedEntry);

            // Per-session script-output evidence bundle (JSON + MD) cited by the report.
            try {
                TrinetraEvidence.recordStatEvidence(sanitized, finding, effectiveVendorCanon, target);
            } catch (Exception ex) {
                TrinetraCommon.logWarn("Evidence bundle write failed for " + code + ": " + ex.getMessage());
            }
        } else {
            TrinetraCommon.logError(code + " -> Failed to append finding to session JSON");
        }

        // Update brain state via trinetra_brain
        TrinetraBrain.updateBrain(sanitized);
        if (autoConnected) {
            try { effectiveConnector.disconnect(); } catch (Exception ignored) {}
        }

        return finding;
    }

    // ── Run all stat-owned tests ──
    public static List<Map<String, Object>> statRunAll(String sessionName, String target) {
        return statRunAll(sessionName, target, null, 1, null);
    }

    /**
     * Run a batch of tests with optional subset selection and optional
     * parallelism.
     *
     * Selection semantics (Prompt 12):
     *  - selection == null/empty  -> legacy behavior: every known test,
     *    executed sequentially in code order (unchanged default).
     *  - selection non-empty      -> ONLY those ids execute (never invoked
     *    at all when unselected, so they cannot appear in findings,
     *    already_run_v_codes, or any brain-state entry); runs proceed on a
     *    thread pool of `workers` threads. Ids not defined in the stat
     *    engine are skipped with a warning and leave no trace.
     *
     * Each executed test produces one audit_log row via the Prompt 11
     * SQLite path (when userId != null).
     */
    public static List<Map<String, Object>> statRunAll(String sessionName, String target,
                                                       Set<String> selection, int workers,
                                                       String userId) {
        loadDefinitions();

        String sanitized = TrinetraCommon.sanitizeName(sessionName);
        List<Map<String, Object>> results = new ArrayList<>();

        // ── Plan: decide which codes execute at all ──
        List<String> allCodes = new ArrayList<>(testDefinitions.keySet());
        Collections.sort(allCodes);

        boolean selecting = selection != null && !selection.isEmpty();

        // ── Vendor connector resolution (Prompt 13) ──
        // Multi-vendor fix: resolve per device (target) — device_vendors
        // map takes precedence so that two statRunAll invocations on the
        // same combined session but different device targets each stamp
        // their own correct vendor (no cross-vendor leakage). Legacy
        // single-vendor sessions fall back to session-level
        // vendor_resolution exactly as before.
        String effectiveVendorRaw = TrinetraSession.getEffectiveVendorForDevice(sanitized, target);
        if (effectiveVendorRaw == null || effectiveVendorRaw.isBlank()) {
            effectiveVendorRaw = TrinetraSession.getSessionFinalVendor(sanitized);
        }
        VendorConnector connector = VendorConnectorRegistry.resolve(effectiveVendorRaw);
        Map<String, String> vendorEnv = new HashMap<>();
        vendorEnv.put("TRINETRA_VENDOR", connector.getVendorName());
        vendorEnv.put("TRINETRA_VENDOR_REQUESTED", effectiveVendorRaw);
        vendorEnv.put("TRINETRA_CONNECTOR",
            connector.getClass().getSimpleName());
        try {
            connector.connect(target, new HashMap<>());
        } catch (Exception e) {
            TrinetraCommon.logWarn("Connector connect failed ("
                + connector.getVendorName() + "): " + e.getMessage());
        }

        List<String> plan = new ArrayList<>();
        if (!selecting) {
            plan.addAll(allCodes);
        } else {
            Set<String> wanted = new LinkedHashSet<>();
            for (String s : selection) {
                String c = s == null ? "" : s.trim().toUpperCase();
                if (!c.isEmpty()) wanted.add(c);
            }
            for (String c : allCodes)
                if (wanted.contains(c)) plan.add(c);

            for (String c : wanted)
                if (!plan.contains(c))
                    TrinetraCommon.logWarn("Skipping unknown test id: " + c);
            Collections.sort(plan);
        }

        // ── Execute ──
        boolean parallel = selecting && workers > 1 && plan.size() > 1;
        if (!parallel) {
            int total = plan.size(), current = 0;
            for (String code : plan) {
                current++;
                TrinetraCommon.logInfo("[" + current + "/" + total + "] Running " + code + "...");
                Map<String, Object> result = runOne(code, sanitized, target, vendorEnv);
                results.add(result);
                String verdict = resultVerdict(result);
                System.out.println("  [" + current + "/" + total + "] "
                    + code + " -> " + verdict.toUpperCase());
            }
        } else {
            int nThreads = Math.min(workers, plan.size());
            ExecutorService pool = Executors.newFixedThreadPool(nThreads);
            TrinetraCommon.logInfo("Running " + plan.size() + " selected tests on "
                + nThreads + " workers");
            try {
                List<Future<Map<String, Object>>> futures = new ArrayList<>();
                for (String code : plan)
                    futures.add(pool.submit(() ->
                        runOne(code, sanitized, target, vendorEnv)));
                for (Future<Map<String, Object>> f : futures)
                    results.add(f.get());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                TrinetraCommon.logError("Parallel run interrupted: " + e.getMessage());
            } catch (ExecutionException e) {
                TrinetraCommon.logError("Parallel run failed: " + e.getCause());
            } finally {
                pool.shutdownNow();
            }
        }

        // ── One audit row per executed test (Prompt 11 path) ──
        if (userId != null) {
            for (Map<String, Object> r : results) {
                String code = TrinetraCommon.getString(r, "v_code",
                    TrinetraCommon.getString(r, "test_code", "?"));
                TrinetraAudit.testExecuted(userId, sanitized, code, resultVerdict(r));
            }
        }

        try { connector.disconnect(); } catch (Exception ignored) {}

        // ── Summary ──
        int pass = 0, fail = 0, review = 0, err = 0;
        for (Map<String, Object> r : results) {
            switch (resultVerdict(r)) {
                case "pass": case "success": pass++; break;
                case "fail": case "failed": fail++; break;
                case "manual_review": review++; break;
                default: err++; break;
            }
        }

        System.out.println("\n=== Stat Run Complete ===");
        System.out.println("Total: " + results.size() + " | Pass: " + pass + " | Fail: " + fail
            + " | Manual Review: " + review + " | Error: " + err);

        return results;
    }

    /**
     * Multi-vendor batch helper — runs the same or different test
     * selections across multiple device targets within ONE session.
     * Each (device, test) pair executes via statRun with that device's
     * effective vendor, so a shared vendor-agnostic test_id run on
     * both Cisco and Juniper yields two distinct normalized_results
     * entries (device_id + vendor correctly segregated). The chain
     * remains a single tamper-evident sequence across all devices.
     *
     * @param sessionName session to write into
     * @param deviceTargets ordered list of device identifiers (used as
     *                      device_id / target address; must have a
     *                      device_vendors entry or a session-level
     *                      vendor_resolution fallback)
     * @param selection tests to run per device (same selection for
     *                  every device; use perDeviceSelection overload for
     *                  heterogenous mixes)
     * @param workers parallelism per device batch (1 = sequential)
     * @param userId audit identity or null to skip audit rows
     */
    public static List<Map<String, Object>> statRunAllAcrossDevices(
            String sessionName,
            List<String> deviceTargets,
            Set<String> selection,
            int workers,
            String userId) {
        Map<String, Set<String>> perDevice = new LinkedHashMap<>();
        for (String d : deviceTargets) perDevice.put(d, selection);
        return statRunAllAcrossDevicesPerSelection(sessionName, perDevice, workers, userId);
    }

    /**
     * Heterogenous variant: each device may have a different test mix.
     * Enables the "vendor-agnostic shared test + vendor-specific test
     * per vendor" requirement in one call.
     */
    public static List<Map<String, Object>> statRunAllAcrossDevicesPerSelection(
            String sessionName,
            Map<String, Set<String>> perDeviceSelection,
            int workers,
            String userId) {
        List<Map<String, Object>> combined = new ArrayList<>();
        for (Map.Entry<String, Set<String>> e : perDeviceSelection.entrySet()) {
            String device = e.getKey();
            Set<String> sel = e.getValue();
            List<Map<String, Object>> part = statRunAll(sessionName, device, sel, workers, userId);
            combined.addAll(part);
        }
        return combined;
    }

    /** Route one test id to its engine and normalize the result map. */
    private static Map<String, Object> runOne(String code, String sanitizedSession,
                                               String target, Map<String, String> vendorEnv) {
        if (testDefinitions.containsKey(code)) {
            Map<String, Object> r = statRun(code, sanitizedSession, target, vendorEnv);
            r.put("engine", "stat");
            return r;
        }
        // Should not happen (planner filters), but stay safe and traceable.
        Map<String, Object> skipped = TrinetraCommon.newMap();
        skipped.put("v_code", code);
        skipped.put("verdict", "skipped");
        skipped.put("engine", "none");
        return skipped;
    }

    private static String resultVerdict(Map<String, Object> result) {
        String v = TrinetraCommon.getString(result, "verdict", "");
        if (!v.isEmpty()) return v;
        v = TrinetraCommon.getString(result, "status", "");
        return v.isEmpty() ? "error" : v;
    }

    /**
     * Structured catalog of every runnable test id, for --list-tests /
     * future UI consumption: {id, description, category, engine} where
     * engine is "stat" (defined in static_map/decision_engine).
     */
    public static String listTestsJson() {
        loadDefinitions();
        List<Object> out = new ArrayList<>();
        for (TestDefinition d : testDefinitions.values()) {
            Map<String, Object> e = TrinetraCommon.newMap();
            e.put("id", d.code);
            e.put("description", d.name);
            e.put("category", d.category);
            e.put("engine", "stat");
            out.add(e);
        }
        return TrinetraJson.prettyJson(out);
    }

    // ── Status report ──
    public static String statStatus(String sessionName) {
        String sanitized = TrinetraCommon.sanitizeName(sessionName);
        List<Map<String, Object>> findings = TrinetraSession.getFindings(sanitized);

        int total = 0, pass = 0, fail = 0, manualReview = 0, error = 0;
        List<String> statCodes = new ArrayList<>();

        for (Map<String, Object> f : findings) {
            String engine = TrinetraCommon.getString(f, "engine", "");
            if (!"trinetra_stat".equals(engine)) continue;

            total++;
            String verdict = TrinetraCommon.getString(f, "verdict", "error");
            String code = TrinetraCommon.getString(f, "v_code", "???");
            statCodes.add(code);

            switch (verdict) {
                case "pass": pass++; break;
                case "fail": fail++; break;
                case "manual_review": manualReview++; break;
                default: error++; break;
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append("=== Stat Engine Status: ").append(sanitized).append(" ===\n\n");
        sb.append("Total stat tests run: ").append(total).append("\n");
        sb.append("  PASS:         ").append(pass).append("\n");
        sb.append("  FAIL:         ").append(fail).append("\n");
        sb.append("  MANUAL_REVIEW:").append(manualReview).append("\n");
        sb.append("  ERROR:        ").append(error).append("\n\n");

        if (!statCodes.isEmpty()) {
            sb.append("Tests run: ").append(String.join(", ", statCodes)).append("\n");
        }

        loadDefinitions();
        sb.append("Defined tests: ").append(testDefinitions.size()).append("\n");

        return sb.toString();
    }

    // ── Helpers ──
    @SuppressWarnings("unchecked")
    private static int countFindings(String sessionName) {
        Map<String, Object> session = TrinetraSession.loadSession(sessionName);
        if (session == null) return 0;
        Object f = session.get("findings");
        if (f instanceof List) return ((List<?>) f).size();
        return 0;
    }

    private static Map<String, Object> buildStatFailure(String code, String target, String error) {
        Map<String, Object> finding = TrinetraCommon.newMap();
        finding.put("finding_id", UUID.randomUUID().toString());
        finding.put("v_code", code);
        finding.put("test_code", code);
        finding.put("v_name", code);
        finding.put("target", target);
        finding.put("script", "stat_scripts/" + code + ".sh");
        finding.put("started_at", TrinetraCommon.nowIso());
        finding.put("ended_at", TrinetraCommon.nowIso());
        finding.put("exit_code", -1);
        finding.put("success", false);
        finding.put("status", "error");
        finding.put("verdict", "error");
        finding.put("verdict_detail", error);
        finding.put("raw_output", error);
        finding.put("raw_stderr", error);
        finding.put("stdout", error);
        finding.put("stderr", error);
        finding.put("summary", error);
        finding.put("summary_status", "error");
        finding.put("artifacts", TrinetraCommon.newList());
        finding.put("tags", TrinetraCommon.newList());
        finding.put("engine", "trinetra_stat");
        return finding;
    }

    /**
     * List all stat-owned test codes.
     */
    public static List<String> listStatCodes() {
        loadDefinitions();
        List<String> codes = new ArrayList<>(testDefinitions.keySet());
        Collections.sort(codes);
        return codes;
    }

    /**
     * Check if a code is stat-owned (exists in static_map/decision_engine).
     */
    public static boolean isStatCode(String code) {
        loadDefinitions();
        return testDefinitions.containsKey(code.toUpperCase());
    }
}
