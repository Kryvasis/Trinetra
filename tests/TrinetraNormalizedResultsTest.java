import java.nio.file.*;
import java.util.*;

/**
 * Tests for the optional brain-state `normalized_results` field.
 *
 * Run with:
 *   javac -cp out -d out tests/TrinetraNormalizedResultsTest.java
 *   java -Dtrinetra.root=<temp-root> -cp out TrinetraNormalizedResultsTest
 *
 * Covers:
 *  (a) appending an entry persists it to brain_state_<name>.json,
 *  (b) all 14 required brain-state fields remain intact/valid after append,
 *  (c) an old brain-state file without normalized_results loads and
 *      validates cleanly (treated as empty array).
 */
public class TrinetraNormalizedResultsTest {

    private static final List<String> REQUIRED_14 = List.of(
        "session_name", "target", "state", "last_updated",
        "byte_size", "estimated_tokens", "compression_count",
        "already_run_v_codes", "confirmed_findings", "suspected_findings",
        "counts", "latest_suggestion", "suggestion_history", "latest_score");

    private static int failures = 0;

    private static void expect(boolean cond, String what) {
        if (cond) {
            System.out.println("  [ok] " + what);
        } else {
            System.err.println("  [FAIL] " + what);
            failures++;
        }
    }

    private static Map<String, Object> sampleEntry(String deviceId) {
        Map<String, Object> e = new LinkedHashMap<>();
        e.put("device_id", deviceId);
        e.put("vendor", "Cisco");
        e.put("test_id", "V-003");
        e.put("raw_output", "raw banner bytes here");
        e.put("normalized_result", "pass");
        return e; // timestamp intentionally omitted -> must be auto-filled
    }

    public static void main(String[] args) throws Exception {
        Path root = Path.of(System.getProperty("trinetra.root"));
        System.out.println("=== TrinetraNormalizedResultsTest ===");
        System.out.println("root: " + root + "\n");

        // ── Prepare a scored session via the real lifecycle API ──
        String name = "nrt_test";
        TrinetraSession.createSession(name, "127.0.0.1");

        // Simulate a completed scoring run so latest_score exists
        // (in production TrinetraBrain writes this field).
        Path statePath = TrinetraCommon.sessionBrainState(name);
        Map<String, Object> state = TrinetraCommon.readJsonFile(statePath);
        state.put("state", TrinetraSession.State.BRAIN_UPDATED.value);
        state.put("latest_score", TrinetraCommon.mapOf(
            "score", "85", "scored_at", TrinetraCommon.nowIso()));
        TrinetraCommon.writeJsonFile(statePath, state);

        // ── (a) Append + persist ────────────────────────────────
        System.out.println("(a) append entry and verify persistence");
        boolean ok = TrinetraSession.appendNormalizedResult(name, sampleEntry("dev-1"));
        expect(ok, "appendNormalizedResult returns true");
        ok = TrinetraSession.appendNormalizedResult(name, sampleEntry("dev-2"));
        expect(ok, "second appendNormalizedResult returns true");

        Map<String, Object> reloaded = TrinetraCommon.readJsonFile(statePath);
        List<Map<String, Object>> results =
            TrinetraCommon.getList(reloaded, TrinetraSession.NORMALIZED_RESULTS_FIELD);
        expect(results.size() == 2,
            "normalized_results persisted with 2 entries (got " + results.size() + ")");

        boolean allKeysPresent = true;
        boolean timestampsFilled = true;
        Set<String> ids = new HashSet<>();
        for (Map<String, Object> r : results) {
            for (String k : List.of("device_id", "vendor", "test_id",
                                    "raw_output", "normalized_result", "timestamp")) {
                if (!r.containsKey(k)) allKeysPresent = false;
            }
            Object ts = r.get("timestamp");
            if (!(ts instanceof String) || ((String) ts).isBlank()) timestampsFilled = false;
            ids.add(String.valueOf(r.get("device_id")));
        }
        expect(allKeysPresent, "every entry has all six schema keys");
        expect(timestampsFilled, "missing timestamps were auto-filled");
        expect(ids.equals(Set.of("dev-1", "dev-2")), "entry payloads round-trip intact");
        expect(TrinetraSession.getNormalizedResults(name).size() == 2,
            "getNormalizedResults reads back the same array");

        // ── (b) 14 required fields untouched and valid ──────────
        System.out.println("\n(b) required fields intact after append");
        List<String> errors = TrinetraSession.validateBrainState(name);
        expect(errors.isEmpty(),
            "validateBrainState clean after append" +
            (errors.isEmpty() ? "" : " -> " + errors));
        boolean allRequired = true;
        for (String f : REQUIRED_14) {
            if (!reloaded.containsKey(f)) {
                allRequired = false;
                System.err.println("    missing after append: " + f);
            }
        }
        expect(allRequired && REQUIRED_14.size() == 14,
            "all 14 required fields still present");
        expect(reloaded.get("session_name").equals(name)
               && reloaded.get("target").equals("127.0.0.1"),
            "field values not clobbered by append");

        // ── (c) Legacy file without the field ───────────────────
        System.out.println("\n(c) legacy brain-state file without normalized_results");
        String legacy = "nrt_legacy";
        Files.createDirectories(TrinetraCommon.sessionDir(legacy));
        Path legacyState = TrinetraCommon.sessionBrainState(legacy);
        StringBuilder old = new StringBuilder();
        old.append("{\n")
           .append("  \"session_name\": \"").append(legacy).append("\",\n")
           .append("  \"target\": \"192.168.1.0/24\",\n")
           .append("  \"state\": \"brain_updated\",\n")
           .append("  \"last_updated\": \"2026-07-01T00:00:00Z\",\n")
           .append("  \"byte_size\": 100,\n")
           .append("  \"estimated_tokens\": 25,\n")
           .append("  \"compression_count\": 0,\n")
           .append("  \"already_run_v_codes\": [],\n")
           .append("  \"confirmed_findings\": [],\n")
           .append("  \"suspected_findings\": [],\n")
           .append("  \"counts\": {\"total_runs\":\"0\",\"success_runs\":\"0\",")
           .append("\"failed_runs\":\"0\",\"unsummarized\":\"0\"},\n")
           .append("  \"latest_suggestion\": null,\n")
           .append("  \"suggestion_history\": [],\n")
           .append("  \"latest_score\": {\"score\": \"72\"}\n")
           .append("}\n");
        TrinetraCommon.writeFile(legacyState, old.toString());

        List<String> legacyErrors = TrinetraSession.validateBrainState(legacy);
        expect(legacyErrors.isEmpty(),
            "old file validates without error" +
            (legacyErrors.isEmpty() ? "" : " -> " + legacyErrors));
        expect(TrinetraSession.getNormalizedResults(legacy).isEmpty(),
            "missing normalized_results treated as empty array");

        // Appending into a legacy file must also work and stay valid.
        expect(TrinetraSession.appendNormalizedResult(legacy, sampleEntry("dev-9")),
            "append works on legacy file");
        expect(TrinetraSession.validateBrainState(legacy).isEmpty(),
            "legacy file valid after first append");

        // Bonus: pre-latest_score legacy file (like demo/ses27_07_26) must
        // report ONLY the known latest_score error, nothing about
        // normalized_results.
        String oldest = "nrt_oldest";
        Files.createDirectories(TrinetraCommon.sessionDir(oldest));
        Path oldestState = TrinetraCommon.sessionBrainState(oldest);
        TrinetraCommon.writeFile(oldestState, buildOldestJson());
        List<String> oldestErrors = TrinetraSession.validateBrainState(oldest);
        expect(oldestErrors.size() == 1
               && oldestErrors.get(0).contains("latest_score"),
            "pre-score file reports only known latest_score error -> "
            + oldestErrors);

        System.out.println();
        if (failures == 0) {
            System.out.println("[+] TrinetraNormalizedResultsTest: all tests passed");
            return;
        }
        System.err.println("[-] TrinetraNormalizedResultsTest: " + failures + " failure(s)");
        System.exit(1);
    }

    /** Old-format file: 13 fields, no latest_score, no normalized_results. */
    private static String buildOldestJson() {
        return "{\n"
            + "  \"session_name\": \"nrt_oldest\",\n"
            + "  \"target\": \"10.0.0.1\",\n"
            + "  \"state\": \"brain_updated\",\n"
            + "  \"last_updated\": \"2026-06-01T00:00:00Z\",\n"
            + "  \"byte_size\": 10,\n"
            + "  \"estimated_tokens\": 3,\n"
            + "  \"compression_count\": 0,\n"
            + "  \"already_run_v_codes\": [],\n"
            + "  \"confirmed_findings\": [],\n"
            + "  \"suspected_findings\": [],\n"
            + "  \"counts\": {\"total_runs\":\"0\",\"success_runs\":\"0\","
            + "\"failed_runs\":\"0\",\"unsummarized\":\"0\"},\n"
            + "  \"latest_suggestion\": null,\n"
            + "  \"suggestion_history\": []\n"
            + "}\n";
    }
}
