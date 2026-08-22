import java.io.*;
import java.nio.file.*;
import java.util.*;

/**
 * Session lifecycle manager.
 * Creates sessions, bootstraps artifacts, manages session JSON, brain state, and global state.
 */
public class TrinetraSession {

    public enum State {
        INITIALIZED("initialized"),
        SESSION_CREATED("session_created"),
        FINDING_RECORDED("finding_recorded"),
        BRAIN_PENDING("brain_pending"),
        BRAIN_UPDATED("brain_updated"),
        SUGGESTION_READY("suggestion_ready"),
        REPORT_READY("report_ready"),
        COMPRESSED("compressed");

        final String value;
        State(String value) { this.value = value; }
    }

    public static Map<String, Object> createSession(String sessionName, String target) {
        String sanitized = TrinetraCommon.sanitizeName(sessionName);
        Path dir = TrinetraCommon.sessionDir(sanitized);
        Path jsonPath = TrinetraCommon.sessionJson(sanitized);

        try { Files.createDirectories(dir); } catch (IOException e) {
            TrinetraCommon.logError("Failed to create session dir: " + e.getMessage());
            return null;
        }
        try { Files.createDirectories(TrinetraCommon.sessionArtifactsDir(sanitized)); } catch (IOException ignored) {}

        Map<String, Object> session = TrinetraCommon.newMap();
        session.put("session_name", sanitized);
        session.put("target", target);
        session.put("created_at", TrinetraCommon.nowIso());
        session.put("updated_at", TrinetraCommon.nowIso());
        session.put("findings", TrinetraCommon.newList());
        session.put("status", "active");

        TrinetraCommon.writeJsonFile(jsonPath, session);

        bootstrapBrainMd(sanitized);
        bootstrapBrainState(sanitized, target);
        refreshGlobalBrainState(sanitized, target, "session_created");

        TrinetraCommon.logInfo("Session created: " + sanitized + " (target: " + target + ")");
        return session;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> loadSession(String sessionName) {
        String sanitized = TrinetraCommon.sanitizeName(sessionName);
        Path jsonPath = TrinetraCommon.sessionJson(sanitized);
        if (!Files.exists(jsonPath)) {
            TrinetraCommon.logError("Session not found: " + sanitized);
            return null;
        }
        return TrinetraCommon.readJsonFile(jsonPath);
    }

    @SuppressWarnings("unchecked")
    public static List<Map<String, Object>> getFindings(String sessionName) {
        Map<String, Object> session = loadSession(sessionName);
        if (session == null) return new ArrayList<>();
        Object f = session.get("findings");
        if (f instanceof List) {
            List<Map<String, Object>> result = new ArrayList<>();
            for (Object item : (List<?>) f) {
                if (item instanceof Map) result.add((Map<String, Object>) item);
            }
            return result;
        }
        return new ArrayList<>();
    }

    public static boolean appendFinding(String sessionName, Map<String, Object> finding) {
        String sanitized = TrinetraCommon.sanitizeName(sessionName);
        Path jsonPath = TrinetraCommon.sessionJson(sanitized);
        Map<String, Object> session = TrinetraCommon.readJsonFile(jsonPath);
        if (session.isEmpty()) return false;

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> findings = (List<Map<String, Object>>) session.get("findings");
        if (findings == null) {
            findings = new ArrayList<>();
            session.put("findings", findings);
        }
        findings.add(finding);
        session.put("updated_at", TrinetraCommon.nowIso());
        session.put("status", "active");

        TrinetraCommon.writeJsonFile(jsonPath, session);
        refreshBrainStateFromSession(sanitized);
        refreshGlobalBrainState(sanitized, TrinetraCommon.getString(session, "target", ""), "finding_recorded");
        return true;
    }

    public static void bootstrapBrainMd(String sessionName) {
        Path brainPath = TrinetraCommon.sessionBrainMd(sessionName);
        if (Files.exists(brainPath)) return;

        Map<String, Object> session = loadSession(sessionName);
        String target = session != null ? TrinetraCommon.getString(session, "target", "unknown") : "unknown";

        String content = String.join("\n",
            "# Audit Brain: " + sessionName,
            "",
            "## Session Overview",
            "- **Target**: " + target,
            "- **Created**: " + TrinetraCommon.nowIso(),
            "- **Status**: Active",
            "",
            "## Findings Summary",
            "_No findings recorded yet._",
            "",
            "## Key Observations",
            "_Audit memory will accumulate here._",
            "",
            "## Recommendations",
            "_Pending first run._",
            ""
        );
        TrinetraCommon.writeFile(brainPath, content);
    }

    public static void bootstrapBrainState(String sessionName, String target) {
        Path statePath = TrinetraCommon.sessionBrainState(sessionName);
        if (Files.exists(statePath)) return;

        Map<String, Object> state = TrinetraCommon.newMap();
        state.put("session_name", sessionName);
        state.put("target", target);
        state.put("state", State.INITIALIZED.value);
        state.put("last_updated", TrinetraCommon.nowIso());
        state.put("brain_md_path", TrinetraCommon.sessionBrainMd(sessionName).toString());
        state.put("brain_backup_path", TrinetraCommon.sessionBrainBackup(sessionName).toString());
        state.put("byte_size", 0);
        state.put("estimated_tokens", 0);
        state.put("compression_count", 0);
        state.put("already_run_v_codes", TrinetraCommon.newList());
        state.put("confirmed_findings", TrinetraCommon.newList());
        state.put("suspected_findings", TrinetraCommon.newList());
        state.put("counts", TrinetraCommon.mapOf(
            "total_runs", "0",
            "success_runs", "0",
            "failed_runs", "0",
            "unsummarized", "0"
        ));
        state.put("latest_suggestion", null);
        state.put("suggestion_history", TrinetraCommon.newList());

        TrinetraCommon.writeJsonFile(statePath, state);
    }

    @SuppressWarnings("unchecked")
    public static void refreshBrainStateFromSession(String sessionName) {
        Path statePath = TrinetraCommon.sessionBrainState(sessionName);
        Map<String, Object> state = TrinetraCommon.readJsonFile(statePath);
        if (state.isEmpty()) return;

        List<Map<String, Object>> findings = getFindings(sessionName);
        List<String> runCodes = new ArrayList<>();
        List<String> confirmed = new ArrayList<>();
        List<String> suspected = new ArrayList<>();
        int totalRuns = 0, successRuns = 0, failedRuns = 0, unsummarized = 0;

        for (Map<String, Object> f : findings) {
            // Handle both Trinetra format (v_code) and hex script format (test_code)
            String vCode = TrinetraCommon.getString(f, "v_code", "");
            if (vCode.isEmpty()) vCode = TrinetraCommon.getString(f, "test_code", "");
            if (!vCode.isEmpty()) runCodes.add(vCode);

            // Handle both status string and success boolean
            String status = TrinetraCommon.getString(f, "status", "");
            if (status.isEmpty()) {
                Object successObj = f.get("success");
                if (successObj instanceof Boolean) {
                    status = (Boolean) successObj ? "success" : "failed";
                } else if (successObj instanceof String) {
                    status = "true".equals(successObj) ? "success" : "failed";
                }
            }
            String summaryStatus = TrinetraCommon.getString(f, "summary_status", "");
            totalRuns++;
            if ("success".equals(status)) {
                successRuns++;
                if ("success".equals(summaryStatus) || "fallback_success".equals(summaryStatus)
                    || summaryStatus.isEmpty()) {
                    confirmed.add(vCode);
                } else {
                    suspected.add(vCode);
                }
            } else {
                failedRuns++;
            }
            if ("captured_but_unsummarized".equals(summaryStatus)) unsummarized++;
        }

        state.put("already_run_v_codes", runCodes);
        state.put("confirmed_findings", confirmed);
        state.put("suspected_findings", suspected);
        state.put("counts", TrinetraCommon.mapOf(
            "total_runs", String.valueOf(totalRuns),
            "success_runs", String.valueOf(successRuns),
            "failed_runs", String.valueOf(failedRuns),
            "unsummarized", String.valueOf(unsummarized)
        ));

        String brainContent = TrinetraCommon.readFileIfExists(TrinetraCommon.sessionBrainMd(sessionName));
        if (brainContent != null) {
            state.put("byte_size", brainContent.length());
            state.put("estimated_tokens", TrinetraCommon.estimateTokens(brainContent));
        }

        state.put("last_updated", TrinetraCommon.nowIso());
        TrinetraCommon.writeJsonFile(statePath, state);
    }

    @SuppressWarnings("unchecked")
    public static void refreshGlobalBrainState(String sessionName, String target, String event) {
        Map<String, Object> global = TrinetraCommon.readJsonFile(TrinetraCommon.GLOBAL_BRAIN_STATE);
        if (global.isEmpty()) {
            global = TrinetraCommon.newMap();
            global.put("last_updated", TrinetraCommon.nowIso());
            global.put("active_sessions", TrinetraCommon.newList());
            global.put("session_count", 0);
            global.put("high_risk_sessions", TrinetraCommon.newList());
            global.put("recent_activity", TrinetraCommon.newList());
        }

        List<String> activeSessions = TrinetraCommon.getStringList(global, "active_sessions");
        if (!activeSessions.contains(sessionName)) {
            activeSessions.add(sessionName);
            global.put("active_sessions", activeSessions);
            global.put("session_count", activeSessions.size());
        }

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> activity = (List<Map<String, Object>>) global.get("recent_activity");
        if (activity == null) {
            activity = new ArrayList<>();
            global.put("recent_activity", activity);
        }

        Map<String, Object> entry = TrinetraCommon.newMap();
        entry.put("session", sessionName);
        entry.put("timestamp", TrinetraCommon.nowIso());
        entry.put("event", event);
        activity.add(entry);

        // Keep only last 20 activity entries
        if (activity.size() > 20) {
            global.put("recent_activity", new ArrayList<>(activity.subList(activity.size() - 20, activity.size())));
        }

        global.put("last_updated", TrinetraCommon.nowIso());
        TrinetraCommon.writeJsonFile(TrinetraCommon.GLOBAL_BRAIN_STATE, global);
    }

    // ── Normalized Results ──

    /**
     * Read the normalized_results array from a session's brain state.
     * Backward compatible: returns an empty list when the field is absent
     * (older brain-state files).
     */
    public static List<Map<String, Object>> getNormalizedResults(String sessionName) {
        Map<String, Object> state = TrinetraCommon.readJsonFile(
            TrinetraCommon.sessionBrainState(sessionName));
        return TrinetraCommon.getList(state, NORMALIZED_RESULTS_FIELD);
    }

    /**
     * Append one entry to the brain-state normalized_results array and
     * persist atomically via TrinetraCommon.writeJsonFile.
     *
     * Entry shape: {device_id, vendor, test_id, raw_output,
     *               normalized_result, timestamp}.  A missing timestamp
     * is filled with the current UTC time.  All existing required
     * brain-state fields are left untouched.
     *
     * @return true on success, false when the brain-state file is
     *         missing/unreadable or the entry is invalid.
     */
    public static boolean appendNormalizedResult(String sessionName,
                                                 Map<String, Object> entry) {
        if (entry == null) return false;
        Path statePath = TrinetraCommon.sessionBrainState(sessionName);
        Map<String, Object> state = TrinetraCommon.readJsonFile(statePath);
        if (state.isEmpty()) {
            TrinetraCommon.logError(
                "Cannot append normalized result, brain state not found: "
                + statePath);
            return false;
        }

        Map<String, Object> record = TrinetraCommon.newMap();
        for (String key : NORMALIZED_RESULT_REQUIRED) {
            Object v = entry.get(key);
            if (v == null && "timestamp".equals(key)) v = TrinetraCommon.nowIso();
            record.put(key, v);
        }

        List<Map<String, Object>> results =
            TrinetraCommon.getList(state, NORMALIZED_RESULTS_FIELD);
        results.add(record);
        state.put(NORMALIZED_RESULTS_FIELD, results);

        state.put("last_updated", TrinetraCommon.nowIso());
        TrinetraCommon.writeJsonFile(statePath, state);   // atomic write
        return true;
    }

    // ── Schema Validation ──

    private static final List<String> SESSION_REQUIRED = List.of("session_name", "target", "created_at", "findings");
    private static final List<String> BRAIN_STATE_REQUIRED = List.of("session_name", "target", "state", "last_updated",
        "byte_size", "estimated_tokens", "compression_count", "already_run_v_codes", "confirmed_findings",
        "suspected_findings", "counts", "latest_suggestion", "suggestion_history", "latest_score");
    private static final List<String> FINDING_REQUIRED = List.of("test_code", "tool", "target", "success");

    // ── Normalized results (optional brain-state extension) ──
    // Optional array; older files without it are treated as empty.
    public static final String NORMALIZED_RESULTS_FIELD = "normalized_results";
    private static final List<String> NORMALIZED_RESULT_REQUIRED =
        List.of("device_id", "vendor", "test_id", "raw_output",
                "normalized_result", "timestamp");

    /** Validate session JSON structure. Returns list of errors (empty = valid). */
    public static List<String> validateSession(String sessionName) {
        List<String> errors = new ArrayList<>();
        Map<String, Object> session = loadSession(sessionName);
        if (session == null) {
            errors.add("Session file not found: " + sessionName);
            return errors;
        }
        for (String field : SESSION_REQUIRED) {
            if (!session.containsKey(field)) {
                errors.add("Missing required field: " + field);
            }
        }
        Object findings = session.get("findings");
        if (!(findings instanceof List)) {
            errors.add("'findings' must be a list");
        } else {
            int i = 0;
            for (Object f : (List<?>) findings) {
                if (!(f instanceof Map)) {
                    errors.add("Finding[" + i + "] must be a JSON object");
                } else {
                    Map<String, Object> fm = (Map<String, Object>) f;
                    for (String req : FINDING_REQUIRED) {
                        if (!fm.containsKey(req)) {
                            errors.add("Finding[" + i + "] missing field: " + req);
                        }
                    }
                }
                i++;
            }
        }
        return errors;
    }

    /** Validate brain_state JSON structure. Returns list of errors (empty = valid). */
    public static List<String> validateBrainState(String sessionName) {
        List<String> errors = new ArrayList<>();
        Path statePath = TrinetraCommon.sessionBrainState(sessionName);
        Map<String, Object> state = TrinetraCommon.readJsonFile(statePath);
        if (state == null || state.isEmpty()) {
            errors.add("Brain state file not found or empty: " + statePath);
            return errors;
        }
        for (String field : BRAIN_STATE_REQUIRED) {
            if (!state.containsKey(field)) {
                errors.add("Missing required field: " + field);
            }
        }
        // Validate state machine value
        String stateVal = TrinetraCommon.getString(state, "state", "");
        boolean validState = false;
        for (State s : State.values()) {
            if (s.value.equals(stateVal)) { validState = true; break; }
        }
        if (!validState) {
            errors.add("Invalid state value: " + stateVal);
        }
        // Validate counts sub-object
        Object counts = state.get("counts");
        if (counts instanceof Map) {
            for (String key : List.of("total_runs", "success_runs", "failed_runs", "unsummarized")) {
                if (!((Map<?, ?>) counts).containsKey(key)) {
                    errors.add("counts missing field: " + key);
                }
            }
        } else {
            errors.add("'counts' must be a JSON object");
        }
        // Optional normalized_results: absent on legacy files -> treated as
        // empty, never a validation error.  Shape-checked only when present.
        Object normalized = state.get(NORMALIZED_RESULTS_FIELD);
        if (normalized != null) {
            if (!(normalized instanceof List)) {
                errors.add("'normalized_results' must be a list");
            } else {
                int i = 0;
                for (Object item : (List<?>) normalized) {
                    if (!(item instanceof Map)) {
                        errors.add("normalized_results[" + i + "] must be a JSON object");
                    } else {
                        Map<?, ?> nm = (Map<?, ?>) item;
                        for (String req : NORMALIZED_RESULT_REQUIRED) {
                            if (!nm.containsKey(req)) {
                                errors.add("normalized_results[" + i + "] missing field: " + req);
                            }
                        }
                    }
                    i++;
                }
            }
        }
        return errors;
    }

    /** Validate all sessions. Returns map of session name -> errors. */
    public static Map<String, List<String>> validateAllSessions() {
        Map<String, List<String>> results = new LinkedHashMap<>();
        Path sessionsDir = TrinetraCommon.SESSIONS_DIR;
        if (!Files.exists(sessionsDir)) return results;
        try (var dirs = Files.list(sessionsDir)) {
            dirs.filter(Files::isDirectory).forEach(dir -> {
                String name = dir.getFileName().toString();
                List<String> errs = validateSession(name);
                errs.addAll(validateBrainState(name));
                if (!errs.isEmpty()) results.put(name, errs);
            });
        } catch (IOException ignored) {}
        return results;
    }
}
