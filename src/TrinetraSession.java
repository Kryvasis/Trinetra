import java.io.*;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;

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
        // Same brain_state_<name>.json as appendNormalizedResult: every
        // writer of that file must share the lock or stale reads can
        // overwrite freshly appended chain links.
        withSessionStateLock(sessionName, () -> {
            doRefreshBrainStateFromSession(sessionName);
            return null;
        });
    }

    @SuppressWarnings("unchecked")
    private static void doRefreshBrainStateFromSession(String sessionName) {
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
        withGlobalStateLock(() -> {
            doRefreshGlobalBrainState(sessionName, target, event);
            return null;
        });
    }

    @SuppressWarnings("unchecked")
    private static void doRefreshGlobalBrainState(String sessionName, String target, String event) {
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

        // Chain-hash this snapshot: SHA256(previous_chain_hash + canonical
        // snapshot). The payload excludes only the new chain_hash itself;
        // previous_chain_hash is part of the hashed content.
        String prevHash =
            TrinetraCommon.getString(global, CHAIN_HASH_FIELD, GENESIS_HASH);
        global.put(PREVIOUS_CHAIN_HASH_FIELD, prevHash);
        global.remove(CHAIN_HASH_FIELD);
        global.put(CHAIN_HASH_FIELD, sha256Hex(prevHash + canonicalJson(global)));

        TrinetraCommon.writeJsonFile(TrinetraCommon.GLOBAL_BRAIN_STATE, global);
    }

    // ── Normalized Results ──

    // ── Write Concurrency ──
    // Two layers, because both concurrency models occur in this codebase:
    //  1. In-process: each `trinetra` test/CLI run may drive concurrent
    //     threads in one JVM. FileChannel locks do NOT arbitrate threads
    //     within a JVM (OverlappingFileLockException), so a per-scope
    //     ReentrantLock serializes threads first.
    //  2. Cross-process: every `trinetra` invocation is a separate OS
    //     process (`exec java ... Trinetra`), so a dedicated <file>.lock
    //     sidecar is locked via FileChannel.lock() for the whole
    //     read-modify-write cycle. A stable sidecar inode is used because
    //     atomic rename (atomicWriteFile) would silently drop a lock held
    //     on the data file itself.
    private static final ConcurrentHashMap<String, ReentrantLock> STATE_LOCKS =
        new ConcurrentHashMap<>();

    /** Serialize one full brain-state read-modify-write cycle for a session. */
    public static <T> T withSessionStateLock(String sessionName,
                                             Supplier<T> action) {
        String key = TrinetraCommon.sanitizeName(
            sessionName == null ? "" : sessionName);
        ReentrantLock inProcess =
            STATE_LOCKS.computeIfAbsent(key, k -> new ReentrantLock());
        inProcess.lock();
        try {
            Path statePath = TrinetraCommon.sessionBrainState(sessionName);
            Path lockPath =
                statePath.resolveSibling(statePath.getFileName() + ".lock");
            return withCrossProcessLock(lockPath, action);
        } finally {
            inProcess.unlock();
        }
    }

    /** Serialize one full global brain-state read-modify-write cycle. */
    public static <T> T withGlobalStateLock(Supplier<T> action) {
        ReentrantLock inProcess = STATE_LOCKS.computeIfAbsent(
            "__global__", k -> new ReentrantLock());
        inProcess.lock();
        try {
            Path globalPath = TrinetraCommon.GLOBAL_BRAIN_STATE;
            Path lockPath =
                globalPath.resolveSibling(globalPath.getFileName() + ".lock");
            return withCrossProcessLock(lockPath, action);
        } finally {
            inProcess.unlock();
        }
    }

    /** Blocking OS-level lock on a stable sidecar file; never rewritten. */
    private static <T> T withCrossProcessLock(Path lockPath, Supplier<T> action) {
        FileChannel ch = null;
        FileLock fl = null;
        try {
            Files.createDirectories(lockPath.getParent());
            ch = FileChannel.open(lockPath, StandardOpenOption.CREATE,
                                  StandardOpenOption.WRITE,
                                  StandardOpenOption.READ);
            fl = ch.lock();   // blocks until granted
        } catch (IOException e) {
            TrinetraCommon.logWarn("Cross-process lock unavailable for "
                + lockPath + ": " + e.getMessage()
                + " — proceeding under in-process lock only");
        }
        try {
            return action.get();
        } finally {
            try { if (fl != null) fl.release(); } catch (IOException ignored) {}
            try { if (ch != null) ch.close(); } catch (IOException ignored) {}
        }
    }


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
        // The whole read -> previous_chain_hash -> hash -> append -> write
        // cycle must be atomic, or two writers can chain off the same stale
        // previous_chain_hash and fork the chain.
        Boolean ok = withSessionStateLock(sessionName,
            () -> doAppendNormalizedResult(sessionName, entry));
        return Boolean.TRUE.equals(ok);
    }

    private static boolean doAppendNormalizedResult(String sessionName,
                                                    Map<String, Object> entry) {
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

        // Previous link: tracked hash first (no re-walk of the array);
        // fall back to the last entry's hash for legacy/hand-edited files;
        // genesis when this is the session's first entry.
        Object tracked = state.get(PREVIOUS_CHAIN_HASH_FIELD);
        String prevHash = tracked instanceof String && !((String) tracked).isBlank()
            ? (String) tracked : null;
        if (prevHash == null) {
            prevHash = results.isEmpty()
                ? GENESIS_HASH
                : TrinetraCommon.getString(results.get(results.size() - 1),
                                           CHAIN_HASH_FIELD, GENESIS_HASH);
        }

        // chain_hash = SHA256(previous_chain_hash + canonical(entry));
        // hashed payload excludes the entry's own chain_hash.
        record.put(CHAIN_HASH_FIELD, sha256Hex(prevHash + canonicalJson(record)));

        results.add(record);
        state.put(NORMALIZED_RESULTS_FIELD, results);
        state.put(PREVIOUS_CHAIN_HASH_FIELD, record.get(CHAIN_HASH_FIELD));

        state.put("last_updated", TrinetraCommon.nowIso());
        TrinetraCommon.writeJsonFile(statePath, state);   // atomic write
        return true;
    }

    // ── Hash Chaining ──

    /** Outcome of verifyChain / verifyGlobalChain. */
    public static class ChainVerifyResult {
        public final boolean intact;
        public final int brokenAtIndex;   // -1 when intact
        public final String detail;

        private ChainVerifyResult(boolean intact, int brokenAtIndex, String detail) {
            this.intact = intact;
            this.brokenAtIndex = brokenAtIndex;
            this.detail = detail;
        }

        static ChainVerifyResult ok(int entries) {
            return new ChainVerifyResult(true, -1,
                "chain intact (" + entries + " link" + (entries == 1 ? "" : "s") + ")");
        }

        static ChainVerifyResult broken(int index, String detail) {
            return new ChainVerifyResult(false, index, detail);
        }

        @Override
        public String toString() {
            return (intact ? "INTACT: " : "BROKEN at index " + brokenAtIndex + ": ")
                + detail;
        }
    }

    /** Lowercase hex SHA-256 of the UTF-8 input. */
    public static String sha256Hex(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest =
                md.digest(input.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("JVM is missing SHA-256", e);
        }
    }

    /**
     * Canonical JSON: object keys sorted alphabetically at every level,
     * no whitespace — same content always produces the same string.
     */
    public static String canonicalJson(Object val) {
        StringBuilder sb = new StringBuilder();
        appendCanonical(sb, val);
        return sb.toString();
    }

    private static void appendCanonical(StringBuilder sb, Object val) {
        if (val == null) {                       sb.append("null"); }
        else if (val instanceof Map<?, ?> m) {
            TreeMap<String, Object> sorted = new TreeMap<>();
            for (Map.Entry<?, ?> e : m.entrySet())
                sorted.put(String.valueOf(e.getKey()), e.getValue());
            sb.append('{');
            boolean first = true;
            for (Map.Entry<String, Object> e : sorted.entrySet()) {
                if (!first) sb.append(',');
                first = false;
                appendCanonical(sb, e.getKey());
                sb.append(':');
                appendCanonical(sb, e.getValue());
            }
            sb.append('}');
        }
        else if (val instanceof List<?> l) {
            sb.append('[');
            boolean first = true;
            for (Object o : l) {
                if (!first) sb.append(',');
                first = false;
                appendCanonical(sb, o);
            }
            sb.append(']');
        }
        else if (val instanceof String s)        { appendJsonString(sb, s); }
        else if (val instanceof Boolean b)       { sb.append(b); }
        else if (val instanceof Number n)        { sb.append(n); }
        else                                     { appendJsonString(sb, val.toString()); }
    }

    private static void appendJsonString(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
            case '"':  sb.append("\\\""); break;
            case '\\': sb.append("\\\\"); break;
            case '\n': sb.append("\\n"); break;
            case '\r': sb.append("\\r"); break;
            case '\t': sb.append("\\t"); break;
            default:
                if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                else sb.append(c);
            }
        }
        sb.append('"');
    }

    private static Map<String, Object> withoutField(Map<String, Object> entry) {
        Map<String, Object> copy = new LinkedHashMap<>(entry);
        copy.remove(CHAIN_HASH_FIELD);
        return copy;
    }

    /**
     * Walk the session's normalized_results entries in order, recomputing
     * each chain_hash from its predecessor's stored hash (genesis for the
     * first). Returns the first break point, or intact.
     */
    public static ChainVerifyResult verifyChain(String sessionName) {
        Map<String, Object> state = TrinetraCommon.readJsonFile(
            TrinetraCommon.sessionBrainState(sessionName));
        if (state.isEmpty()) {
            return ChainVerifyResult.broken(-1,
                "brain state not found or unreadable");
        }

        List<Map<String, Object>> entries =
            TrinetraCommon.getList(state, NORMALIZED_RESULTS_FIELD);

        String prevHash = GENESIS_HASH;
        for (int i = 0; i < entries.size(); i++) {
            Map<String, Object> e = entries.get(i);
            String stored = TrinetraCommon.getString(e, CHAIN_HASH_FIELD, "");
            String expected = sha256Hex(prevHash + canonicalJson(withoutField(e)));
            if (!expected.equals(stored)) {
                return ChainVerifyResult.broken(i,
                    "entry hash mismatch (expected " + expected
                    + ", stored " + stored + ")");
            }
            prevHash = stored;
        }

        // Tracker must reference the current tip of the chain.
        if (!entries.isEmpty()) {
            String tracker = state.get(PREVIOUS_CHAIN_HASH_FIELD) instanceof String
                ? (String) state.get(PREVIOUS_CHAIN_HASH_FIELD) : null;
            if (tracker != null && !tracker.equals(prevHash)) {
                return ChainVerifyResult.broken(entries.size() - 1,
                    "previous_chain_hash tracker mismatch");
            }
        }
        return ChainVerifyResult.ok(entries.size());
    }

    /**
     * Verify the global brain-state snapshot chain: the stored chain_hash
     * must equal SHA256(stored previous_chain_hash + canonical snapshot).
     */
    public static ChainVerifyResult verifyGlobalChain() {
        Map<String, Object> global =
            TrinetraCommon.readJsonFile(TrinetraCommon.GLOBAL_BRAIN_STATE);
        if (global.isEmpty()) {
            return ChainVerifyResult.ok(0);   // nothing written yet
        }
        Object storedObj = global.get(CHAIN_HASH_FIELD);
        Object prevObj = global.get(PREVIOUS_CHAIN_HASH_FIELD);
        if (!(storedObj instanceof String)) {
            return ChainVerifyResult.ok(0);   // legacy file, chain not yet established
        }
        if (!(prevObj instanceof String)) {
            return ChainVerifyResult.broken(0, "missing previous_chain_hash");
        }

        Map<String, Object> payload = new LinkedHashMap<>(global);
        payload.remove(CHAIN_HASH_FIELD);
        String expected = sha256Hex((String) prevObj + canonicalJson(payload));
        if (!expected.equals(storedObj)) {
            return ChainVerifyResult.broken(0,
                "snapshot hash mismatch (expected " + expected
                + ", stored " + storedObj + ")");
        }
        return ChainVerifyResult.ok(1);
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

    // ── Hash chain (tamper-evident write log) ──
    // Optional fields; older files without them simply have no chain yet.
    public static final String CHAIN_HASH_FIELD = "chain_hash";
    public static final String PREVIOUS_CHAIN_HASH_FIELD = "previous_chain_hash";
    public static final String GENESIS_HASH = sha256Hex("TRINETRA_GENESIS");

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
