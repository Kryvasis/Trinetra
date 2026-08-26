import java.io.*;
import java.nio.file.*;
import java.util.*;

/**
 * Brain update engine — trinetra_brain.java
 * Handles incremental markdown patching, compression, brain state refresh,
 * AI-powered querying, suggestion engine, and CVE/certificate-based scoring.
 *
 * API:
 *   brainUpdate(sessionName)      -> incremental append/patch or compress
 *   brainCompress(sessionName)    -> full read + regenerate when threshold exceeded
 *   brainRead(sessionName, query) -> answer from existing brain + state
 *   brainSuggest(sessionName, query) -> next-step suggestions
 *   brainOverall(query)           -> cross-session answer from global brain_state.json
 *   brainScore(sessionName)       -> certificate/CVE-based scoring pass
 */
public class TrinetraBrain {

    private static final long COMPRESS_BYTE_THRESHOLD = TrinetraCommon.BRAIN_COMPRESS_BYTE_DEFAULT;
    private static final long COMPRESS_TOKEN_THRESHOLD = TrinetraCommon.BRAIN_COMPRESS_TOKEN_DEFAULT;

    @SuppressWarnings("unchecked")
    public static boolean updateBrain(String sessionName) {
        String sanitized = TrinetraCommon.sanitizeName(sessionName);
        // Entire brain-state read-modify-write cycle runs under the session
        // lock: patch/compress rewrite the whole brain_state_<s>.json file,
        // so an unlocked run can clobber normalized_results appended by a
        // concurrent writer (lost-update race caught by test matrices).
        Boolean ok = TrinetraSession.withSessionStateLock(sanitized,
            () -> doUpdateBrain(sanitized));
        return Boolean.TRUE.equals(ok);
    }

    /** Unlocked internal: caller must hold the session state lock. */
    private static Boolean doUpdateBrain(String sanitized) {
        Path statePath = TrinetraCommon.sessionBrainState(sanitized);

        Map<String, Object> session = TrinetraSession.loadSession(sanitized);
        if (session == null) {
            TrinetraCommon.logError("Cannot update brain: session not found: " + sanitized);
            return false;
        }

        Map<String, Object> state = TrinetraCommon.readJsonFile(statePath);
        List<Map<String, Object>> findings = TrinetraSession.getFindings(sanitized);

        // Already inside the session lock: use the unlocked variant so the
        // FileChannel sidecar is not re-acquired mid-cycle.
        TrinetraSession.doRefreshBrainStateFromSession(sanitized);
        state = TrinetraCommon.readJsonFile(statePath);

        long byteSize = getLongVal(state, "byte_size", 0);
        long tokenEst = getLongVal(state, "estimated_tokens", 0);

        if (byteSize > COMPRESS_BYTE_THRESHOLD || tokenEst > COMPRESS_TOKEN_THRESHOLD) {
            TrinetraCommon.logInfo("Brain threshold exceeded, compressing: " + sanitized
                + " (bytes=" + byteSize + ", tokens=" + tokenEst + ")");
            return compressBrain(sanitized, session, findings, state);
        }

        return patchBrainIncremental(sanitized, session, findings, state);
    }

    private static boolean patchBrainIncremental(String sessionName, Map<String, Object> session,
                                                  List<Map<String, Object>> findings,
                                                  Map<String, Object> state) {
        Path brainPath = TrinetraCommon.sessionBrainMd(sessionName);
        String existing = TrinetraCommon.readFileIfExists(brainPath);
        if (existing == null) {
            TrinetraSession.bootstrapBrainMd(sessionName);
            existing = TrinetraCommon.readFileIfExists(brainPath);
        }
        if (existing == null) return false;

        String target = TrinetraCommon.getString(session, "target", "unknown");

        Map<String, Object> latestFinding = null;
        List<String> runCodes = TrinetraCommon.getStringList(state, "already_run_v_codes");
        if (!findings.isEmpty()) {
            latestFinding = findings.get(findings.size() - 1);
        }

        StringBuilder patched = new StringBuilder(existing);

        if (latestFinding != null) {
            String vCode = TrinetraCommon.getString(latestFinding, "v_code",
                TrinetraCommon.getString(latestFinding, "test_code", "unknown"));
            String vName = TrinetraCommon.getString(latestFinding, "v_name", "Unknown");
            String status = TrinetraCommon.getString(latestFinding, "status", "unknown");
            String summary = TrinetraCommon.getString(latestFinding, "summary", null);

            String findingLine = "- **" + vCode + "** (" + vName + "): " + status;
            if (summary != null && !summary.isEmpty()) {
                findingLine += " — " + truncate(summary, 200);
            }

            String marker = "## Findings Summary";
            int idx = patched.indexOf(marker);
            if (idx >= 0) {
                int insertPoint = patched.indexOf("\n##", idx + marker.length());
                if (insertPoint < 0) insertPoint = patched.length();
                String codeMarker = "**" + vCode + "**";
                if (!patched.substring(idx, insertPoint).contains(codeMarker)) {
                    String placeholder = "_No findings recorded yet._";
                    int phIdx = patched.indexOf(placeholder, idx);
                    if (phIdx >= 0 && phIdx < insertPoint) {
                        patched.replace(phIdx, phIdx + placeholder.length() + 1, "");
                        insertPoint = patched.indexOf("\n##", idx + marker.length());
                        if (insertPoint < 0) insertPoint = patched.length();
                    }
                    patched.insert(insertPoint, "\n" + findingLine);
                }
            }
        }

        String totalRuns = TrinetraCommon.getString(TrinetraCommon.getMap(state, "counts"), "total_runs", "0");
        String successRuns = TrinetraCommon.getString(TrinetraCommon.getMap(state, "counts"), "success_runs", "0");

        String overviewMarker = "## Session Overview";
        int ovIdx = patched.indexOf(overviewMarker);
        if (ovIdx >= 0) {
            int endIdx = patched.indexOf("\n##", ovIdx + overviewMarker.length());
            if (endIdx < 0) endIdx = patched.length();
            String section = patched.substring(ovIdx, endIdx);
            section = section.replaceAll("- \\*\\*Status\\*\\*:.*", "- **Status**: Active (" + totalRuns + " runs, " + successRuns + " succeeded)");
            patched.replace(ovIdx, endIdx, section);
        }

        state.put("state", TrinetraSession.State.BRAIN_UPDATED.value);
        state.put("last_updated", TrinetraCommon.nowIso());
        TrinetraCommon.writeJsonFile(TrinetraCommon.sessionBrainState(sessionName), state);

        TrinetraCommon.atomicWriteFile(brainPath, patched.toString());
        TrinetraCommon.logInfo("Brain incrementally patched: " + sessionName);
        return true;
    }

    @SuppressWarnings("unchecked")
    private static boolean compressBrain(String sessionName, Map<String, Object> session,
                                         List<Map<String, Object>> findings,
                                         Map<String, Object> state) {
        Path brainPath = TrinetraCommon.sessionBrainMd(sessionName);
        Path backupPath = TrinetraCommon.sessionBrainBackup(sessionName);

        String existing = TrinetraCommon.readFileIfExists(brainPath);
        if (existing != null) {
            TrinetraCommon.atomicWriteFile(backupPath, existing);
        }

        String target = TrinetraCommon.getString(session, "target", "unknown");
        String compressed = generateCompressedBrain(sessionName, target, findings, state);

        TrinetraCommon.atomicWriteFile(brainPath, compressed);

        int compressionCount = TrinetraCommon.getInt(state, "compression_count", 0) + 1;
        state.put("compression_count", compressionCount);
        state.put("byte_size", compressed.length());
        state.put("estimated_tokens", TrinetraCommon.estimateTokens(compressed));
        state.put("state", TrinetraSession.State.COMPRESSED.value);
        state.put("last_updated", TrinetraCommon.nowIso());
        TrinetraCommon.writeJsonFile(TrinetraCommon.sessionBrainState(sessionName), state);

        TrinetraCommon.logInfo("Brain compressed: " + sessionName + " (compression #" + compressionCount + ")");
        return true;
    }

    private static String generateCompressedBrain(String sessionName, String target,
                                                   List<Map<String, Object>> findings,
                                                   Map<String, Object> state) {
        StringBuilder sb = new StringBuilder();
        sb.append("# Audit Brain: ").append(sessionName).append("\n\n");

        sb.append("## Session Overview\n");
        sb.append("- **Target**: ").append(target).append("\n");
        sb.append("- **Created**: ").append(TrinetraCommon.getString(state, "last_updated", TrinetraCommon.nowIso())).append("\n");
        sb.append("- **Status**: Active\n\n");

        sb.append("## Findings Summary\n");
        if (findings.isEmpty()) {
            sb.append("_No findings recorded yet._\n\n");
        } else {
            for (Map<String, Object> f : findings) {
                String vCode = TrinetraCommon.getString(f, "v_code", "???");
                String vName = TrinetraCommon.getString(f, "v_name", "Unknown");
                String status = TrinetraCommon.getString(f, "status", "unknown");
                String summary = TrinetraCommon.getString(f, "summary", null);
                sb.append("- **").append(vCode).append("** (").append(vName).append("): ").append(status);
                if (summary != null && !summary.isEmpty()) {
                    sb.append(" — ").append(truncate(summary, 150));
                }
                sb.append("\n");
            }
            sb.append("\n");
        }

        sb.append("## Counts\n");
        Map<String, Object> counts = TrinetraCommon.getMap(state, "counts");
        sb.append("- Total runs: ").append(TrinetraCommon.getString(counts, "total_runs", "0")).append("\n");
        sb.append("- Successful: ").append(TrinetraCommon.getString(counts, "success_runs", "0")).append("\n");
        sb.append("- Failed: ").append(TrinetraCommon.getString(counts, "failed_runs", "0")).append("\n");
        sb.append("- Unsummarized: ").append(TrinetraCommon.getString(counts, "unsummarized", "0")).append("\n\n");

        List<String> runCodes = TrinetraCommon.getStringList(state, "already_run_v_codes");
        sb.append("## Completed V-Codes\n");
        if (runCodes.isEmpty()) {
            sb.append("_None yet._\n\n");
        } else {
            sb.append(String.join(", ", runCodes)).append("\n\n");
        }

        Map<String, Object> suggestion = TrinetraCommon.getMap(state, "latest_suggestion");
        sb.append("## Latest Suggestion\n");
        if (suggestion.isEmpty() || suggestion.get("next_v_code") == null) {
            sb.append("_No suggestion yet._\n\n");
        } else {
            sb.append("- Next: ").append(TrinetraCommon.getString(suggestion, "next_v_code", "?")).append("\n");
            sb.append("- Reason: ").append(TrinetraCommon.getString(suggestion, "reason", "n/a")).append("\n");
            sb.append("- Confidence: ").append(TrinetraCommon.getString(suggestion, "confidence", "low")).append("\n\n");
        }

        sb.append("_Compressed at ").append(TrinetraCommon.nowIso()).append("_\n");
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    public static String queryBrain(String sessionName, String query) {
        String sanitized = TrinetraCommon.sanitizeName(sessionName);
        String brainContent = TrinetraCommon.readFileIfExists(TrinetraCommon.sessionBrainMd(sanitized));
        Map<String, Object> state = TrinetraCommon.readJsonFile(TrinetraCommon.sessionBrainState(sanitized));

        if (brainContent == null) return "No brain found for session: " + sanitized;

        StringBuilder prompt = new StringBuilder();
        prompt.append("You are an audit assistant. Answer the following query based on the session audit state below.\n\n");
        prompt.append("SESSION BRAIN:\n").append(brainContent).append("\n\n");
        prompt.append("SESSION STATE:\n").append(TrinetraJson.prettyJson(state)).append("\n\n");
        prompt.append("QUERY: ").append(query).append("\n\n");
        prompt.append("Answer concisely, grounded only in the provided session state. If the information is not available, say so.");

        String aiResponse = TrinetraCommon.execGemini(prompt.toString());
        if (aiResponse != null && !aiResponse.isBlank()) {
            return aiResponse;
        }

        return "AI unavailable. Raw brain content:\n\n" + brainContent;
    }

    @SuppressWarnings("unchecked")
    public static String queryOverall(String query) {
        Map<String, Object> globalState = TrinetraCommon.readJsonFile(TrinetraCommon.GLOBAL_BRAIN_STATE);
        if (globalState.isEmpty()) return "No global activity recorded yet.";

        StringBuilder prompt = new StringBuilder();
        prompt.append("You are an audit portfolio assistant. Answer based on the global Trinetra activity state.\n\n");
        prompt.append("GLOBAL STATE:\n").append(TrinetraJson.prettyJson(globalState)).append("\n\n");
        prompt.append("QUERY: ").append(query).append("\n\n");
        prompt.append("Answer concisely, grounded only in the provided global state.");

        String aiResponse = TrinetraCommon.execGemini(prompt.toString());
        if (aiResponse != null && !aiResponse.isBlank()) {
            return aiResponse;
        }
        return "AI unavailable. Raw global state:\n\n" + TrinetraJson.prettyJson(globalState);
    }

    @SuppressWarnings("unchecked")
    public static String suggestNext(String sessionName) {
        String sanitized = TrinetraCommon.sanitizeName(sessionName);
        // Suggestion persistence rewrites the whole brain-state file; hold
        // the session lock for the full read-modify-write cycle.
        return TrinetraSession.withSessionStateLock(sanitized,
            () -> doSuggestNext(sanitized));
    }

    /** Unlocked internal: caller must hold the session state lock. */
    private static String doSuggestNext(String sanitized) {
        Map<String, Object> state = TrinetraCommon.readJsonFile(TrinetraCommon.sessionBrainState(sanitized));
        if (state.isEmpty()) return "No brain state found for session: " + sanitized;

        List<String> runCodes = TrinetraCommon.getStringList(state, "already_run_v_codes");
        Map<String, Object> counts = TrinetraCommon.getMap(state, "counts");
        String target = TrinetraCommon.getString(state, "target", "unknown");

        List<String> allVCodes = TrinetraPen.listVCodes();

        List<String> availableCodes = new ArrayList<>();
        for (String code : allVCodes) {
            if (!runCodes.contains(code)) {
                availableCodes.add(code);
            }
        }

        if (availableCodes.isEmpty()) {
            Map<String, Object> suggestion = TrinetraCommon.newMap();
            suggestion.put("next_v_code", null);
            suggestion.put("reason", "All beta V-codes have been run in this session.");
            suggestion.put("confidence", "high");
            suggestion.put("requires_revalidation", false);
            suggestion.put("based_on", TrinetraCommon.newList());
            state.put("latest_suggestion", suggestion);
            TrinetraCommon.writeJsonFile(TrinetraCommon.sessionBrainState(sanitized), state);
            return "All beta V-codes have been run. Consider revalidating findings or generating a report.";
        }

        StringBuilder prompt = new StringBuilder();
        prompt.append("You are a pentest strategy advisor. Based on the session state, recommend the next V-code to run.\n\n");
        prompt.append("SESSION STATE:\n").append(TrinetraJson.prettyJson(state)).append("\n\n");
        prompt.append("AVAILABLE V-CODES: ").append(String.join(", ", availableCodes)).append("\n\n");
        prompt.append("Already run: ").append(runCodes.isEmpty() ? "none" : String.join(", ", runCodes)).append("\n\n");
        prompt.append("Target: ").append(target).append("\n\n");
        prompt.append("Respond with EXACTLY this JSON format (no markdown, no explanation):\n");
        prompt.append("{\"next_v_code\":\"V-XXX\",\"reason\":\"...\",\"confidence\":\"high|medium|low\","
            + "\"requires_revalidation\":false,\"based_on\":[\"...\"]}\n");

        String aiResponse = TrinetraCommon.execGemini(prompt.toString());
        Map<String, Object> suggestion = parseSuggestion(aiResponse, availableCodes);

        state.put("latest_suggestion", suggestion);
        state.put("state", TrinetraSession.State.SUGGESTION_READY.value);
        state.put("last_updated", TrinetraCommon.nowIso());

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> history = (List<Map<String, Object>>) state.get("suggestion_history");
        if (history == null) {
            history = new ArrayList<>();
            state.put("suggestion_history", history);
        }
        Map<String, Object> historyEntry = TrinetraCommon.newMap();
        historyEntry.put("timestamp", TrinetraCommon.nowIso());
        historyEntry.put("next_v_code", suggestion.get("next_v_code"));
        historyEntry.put("reason", suggestion.get("reason"));
        history.add(historyEntry);
        if (history.size() > 50) {
            state.put("suggestion_history", new ArrayList<>(history.subList(history.size() - 50, history.size())));
        }

        TrinetraCommon.writeJsonFile(TrinetraCommon.sessionBrainState(sanitized), state);

        String nlOutput = String.format(
            "Next recommended V-code: %s\nReason: %s\nConfidence: %s",
            suggestion.get("next_v_code"), suggestion.get("reason"), suggestion.get("confidence"));
        return nlOutput;
    }

    /**
     * CVE/certificate-based scoring pass.
     * Examines findings for CVE matches, certificate issues, and test verdicts
     * to produce a consolidated score.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> brainScore(String sessionName) {
        String sanitized = TrinetraCommon.sanitizeName(sessionName);
        // latest_score is persisted into brain-state; serialize the cycle.
        return TrinetraSession.withSessionStateLock(sanitized,
            () -> doBrainScore(sanitized));
    }

    /** Unlocked internal: caller must hold the session state lock. */
    private static Map<String, Object> doBrainScore(String sanitized) {
        Map<String, Object> session = TrinetraSession.loadSession(sanitized);
        if (session == null) {
            TrinetraCommon.logError("Cannot score brain: session not found: " + sanitized);
            Map<String, Object> err = TrinetraCommon.newMap();
            err.put("error", "Session not found: " + sanitized);
            return err;
        }

        List<Map<String, Object>> findings = TrinetraSession.getFindings(sanitized);
        String target = TrinetraCommon.getString(session, "target", "unknown");

        int totalTests = findings.size();
        int passed = 0, failed = 0, manualReview = 0, errors = 0;
        int criticalCount = 0, highCount = 0, mediumCount = 0, lowCount = 0;
        List<String> cveMatches = new ArrayList<>();
        List<String> certIssues = new ArrayList<>();
        List<Map<String, Object>> failedTests = new ArrayList<>();

        for (Map<String, Object> f : findings) {
            String status = TrinetraCommon.getString(f, "status", "unknown");
            String verdict = TrinetraCommon.getString(f, "verdict", "");
            String vCode = TrinetraCommon.getString(f, "v_code",
                TrinetraCommon.getString(f, "test_code", "???"));

            // Count by status
            if ("pass".equals(verdict) || "success".equals(status)) {
                passed++;
            } else if ("fail".equals(verdict) || "failed".equals(status)) {
                failed++;
                failedTests.add(f);
            } else if ("manual_review".equals(verdict)) {
                manualReview++;
            } else if ("error".equals(verdict) || "error".equals(status)) {
                errors++;
            }

            // Check raw output for CVE patterns
            String rawOutput = TrinetraCommon.getString(f, "raw_output",
                TrinetraCommon.getString(f, "stdout", ""));
            if (rawOutput != null) {
                // CVE detection
                java.util.regex.Matcher cveMatcher = java.util.regex.Pattern
                    .compile("CVE-\\d{4}-\\d{4,}")
                    .matcher(rawOutput);
                while (cveMatcher.find()) {
                    String cve = cveMatcher.group();
                    if (!cveMatches.contains(cve)) {
                        cveMatches.add(cve);
                    }
                }

                // Certificate issue detection
                if (rawOutput.contains("self-signed") || rawOutput.contains("self signed")) {
                    certIssues.add(vCode + ": self-signed certificate");
                }
                if (rawOutput.contains("expired")) {
                    certIssues.add(vCode + ": expired certificate");
                }
                if (rawOutput.contains("weak signature algorithm")) {
                    certIssues.add(vCode + ": weak signature algorithm");
                }
                if (rawOutput.contains("SSLv3") || rawOutput.contains("TLSv1.0") || rawOutput.contains("TLSv1.1")) {
                    certIssues.add(vCode + ": weak TLS version");
                }
                if (rawOutput.contains("NULL") || rawOutput.contains("EXPORT") || rawOutput.contains("RC4")) {
                    certIssues.add(vCode + ": weak cipher suite");
                }
            }

            // Severity from decision engine defaults
            String severity = TrinetraCommon.getString(f, "default_severity",
                TrinetraCommon.getString(f, "severity", "Low"));
            if ("Critical".equalsIgnoreCase(severity)) criticalCount++;
            else if ("High".equalsIgnoreCase(severity)) highCount++;
            else if ("Medium".equalsIgnoreCase(severity)) mediumCount++;
            else lowCount++;
        }

        // Compute composite score
        // Base: 100 points
        // Deductions: Critical=-15, High=-8, Medium=-3, Low=-1
        // CVE match: -10 each
        // Cert issue: -5 each
        int deduction = criticalCount * 15 + highCount * 8 + mediumCount * 3 + lowCount * 1;
        deduction += cveMatches.size() * 10;
        deduction += certIssues.size() * 5;
        int score = Math.max(0, Math.min(100, 100 - deduction));

        // Build result
        Map<String, Object> result = TrinetraCommon.newMap();
        result.put("session_name", sanitized);
        result.put("target", target);
        result.put("score", score);
        result.put("total_tests", totalTests);
        result.put("passed", passed);
        result.put("failed", failed);
        result.put("manual_review", manualReview);
        result.put("errors", errors);
        result.put("critical_count", criticalCount);
        result.put("high_count", highCount);
        result.put("medium_count", mediumCount);
        result.put("low_count", lowCount);
        result.put("cve_matches", cveMatches);
        result.put("cert_issues", certIssues);
        result.put("failed_tests", failedTests);
        result.put("scored_at", TrinetraCommon.nowIso());

        // Persist score into brain state
        Path statePath = TrinetraCommon.sessionBrainState(sanitized);
        Map<String, Object> state = TrinetraCommon.readJsonFile(statePath);
        if (!state.isEmpty()) {
            state.put("latest_score", result);
            state.put("last_updated", TrinetraCommon.nowIso());
            TrinetraCommon.writeJsonFile(statePath, state);
        }

        // Persist into session JSON
        Path jsonPath = TrinetraCommon.sessionJson(sanitized);
        Map<String, Object> sessionData = TrinetraCommon.readJsonFile(jsonPath);
        if (!sessionData.isEmpty()) {
            sessionData.put("scorecard", result);
            sessionData.put("updated_at", TrinetraCommon.nowIso());
            TrinetraCommon.writeJsonFile(jsonPath, sessionData);
        }

        TrinetraCommon.logInfo("Brain scored: " + sanitized + " -> " + score + "/100");
        return result;
    }

    private static Map<String, Object> parseSuggestion(String aiResponse, List<String> availableCodes) {
        Map<String, Object> fallback = TrinetraCommon.newMap();
        if (!availableCodes.isEmpty()) {
            fallback.put("next_v_code", availableCodes.get(0));
            fallback.put("reason", "First available V-code (AI parsing failed)");
            fallback.put("confidence", "low");
        } else {
            fallback.put("next_v_code", null);
            fallback.put("reason", "No V-codes available");
            fallback.put("confidence", "high");
        }
        fallback.put("requires_revalidation", false);
        fallback.put("based_on", TrinetraCommon.newList());

        if (aiResponse == null || aiResponse.isBlank()) return fallback;

        try {
            String cleaned = aiResponse.trim();
            int jsonStart = cleaned.indexOf('{');
            int jsonEnd = cleaned.lastIndexOf('}');
            if (jsonStart >= 0 && jsonEnd > jsonStart) {
                String jsonStr = cleaned.substring(jsonStart, jsonEnd + 1);
                Object parsed = TrinetraJson.parse(jsonStr);
                if (parsed instanceof Map) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> map = (Map<String, Object>) parsed;
                    String suggested = TrinetraCommon.getString(map, "next_v_code", null);
                    if (suggested != null && !availableCodes.contains(suggested)) {
                        map.put("next_v_code", availableCodes.get(0));
                        map.put("reason", TrinetraCommon.getString(map, "reason", "") + " (adjusted: original not available)");
                    }
                    return map;
                }
            }
        } catch (Exception e) {
            TrinetraCommon.logWarn("Failed to parse AI suggestion: " + e.getMessage());
        }
        return fallback;
    }

    private static long getLongVal(Map<String, Object> map, String key, long def) {
        Object v = map.get(key);
        if (v instanceof Number) return ((Number) v).longValue();
        if (v instanceof String) {
            try { return Long.parseLong((String) v); } catch (Exception e) { return def; }
        }
        return def;
    }

    private static String truncate(String s, int maxLen) {
        if (s == null) return "";
        return s.length() <= maxLen ? s : s.substring(0, maxLen - 3) + "...";
    }
}
