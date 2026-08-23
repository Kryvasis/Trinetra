import java.nio.file.*;
import java.util.*;

/**
 * Tests that TrinetraStat.statRun() populates normalized_results
 * (not just direct calls to appendNormalizedResult) and that
 * confirmed_findings/suspected_findings behavior is unchanged.
 *
 * Uses a hermetic synthetic environment inside the temp trinetra.root:
 * a minimal 2_static_map.json defining T-001..T-004 plus matching trivial
 * stat_scripts, same pattern as TrinetraTestSelectionTest.
 *
 * Covers:
 *  (a) single statRun() populates normalized_results, not just findings,
 *  (b) chain_hash is present and verifyChain() passes after statRun(),
 *  (c) parallel statRunAll() preserves chain integrity,
 *  (d) confirmed_findings/suspected_findings are unchanged.
 */
public class TrinetraStatNormalizedResultsTest {

    private static final List<String> CODES =
        List.of("T-001", "T-002", "T-003", "T-004");

    private static int failures = 0;

    private static void expect(boolean cond, String what) {
        if (cond) {
            System.out.println("  [ok] " + what);
        } else {
            System.err.println("  [FAIL] " + what);
            failures++;
        }
    }

    public static void main(String[] args) throws Exception {
        Path root = Path.of(System.getProperty("trinetra.root"));
        System.out.println("=== TrinetraStatNormalizedResultsTest ===");
        System.out.println("root: " + root + "\n");

        setupSyntheticEnv(root);

        // ── (a) single statRun populates normalized_results ──────
        System.out.println("(a) single statRun() populates normalized_results");
        String name = "snr_single";
        TrinetraSession.createSession(name, "10.0.0.1");
        // Simulate scoring so latest_score exists
        Path statePath = TrinetraCommon.sessionBrainState(name);
        Map<String, Object> st = TrinetraCommon.readJsonFile(statePath);
        st.put("state", TrinetraSession.State.BRAIN_UPDATED.value);
        st.put("latest_score", TrinetraCommon.mapOf("score", "80"));
        TrinetraCommon.writeJsonFile(statePath, st);

        Map<String, Object> result = TrinetraStat.statRun("T-001", name, "10.0.0.1");
        expect(result != null, "statRun returned a result");
        String verdict = TrinetraCommon.getString(result, "verdict", "");
        expect(!verdict.isEmpty(), "result has verdict -> " + verdict);

        // findings should exist
        List<Map<String, Object>> findings = TrinetraSession.getFindings(name);
        expect(findings.size() == 1,
            "findings has 1 entry (got " + findings.size() + ")");
        expect("T-001".equals(TrinetraCommon.getString(findings.get(0), "v_code", "")),
            "finding v_code is T-001");

        // normalized_results must ALSO exist (the fix under test)
        List<Map<String, Object>> nr = TrinetraSession.getNormalizedResults(name);
        expect(nr.size() == 1,
            "normalized_results has 1 entry (got " + nr.size() + ")");
        if (!nr.isEmpty()) {
            Map<String, Object> entry = nr.get(0);
            expect("T-001".equals(TrinetraCommon.getString(entry, "test_id", "")),
                "normalized_result test_id is T-001");
            expect("10.0.0.1".equals(TrinetraCommon.getString(entry, "device_id", "")),
                "normalized_result device_id is 10.0.0.1");
            expect(entry.containsKey("vendor"),
                "normalized_result has vendor field");
            expect(entry.containsKey("raw_output"),
                "normalized_result has raw_output field");
            expect(entry.containsKey("normalized_result"),
                "normalized_result has normalized_result field");
            expect(entry.containsKey("timestamp"),
                "normalized_result has timestamp field");
            expect(entry.containsKey("chain_hash"),
                "normalized_result has chain_hash field");
        }

        // chain must be intact
        TrinetraSession.ChainVerifyResult cv = TrinetraSession.verifyChain(name);
        expect(cv.intact, "verifyChain intact after single statRun -> " + cv);

        // ── (b) multiple sequential statRuns build chain ──────────
        System.out.println("\n(b) multiple sequential statRuns build chain");
        String name2 = "snr_multi";
        TrinetraSession.createSession(name2, "10.0.0.2");
        st = TrinetraCommon.readJsonFile(TrinetraCommon.sessionBrainState(name2));
        st.put("state", TrinetraSession.State.BRAIN_UPDATED.value);
        st.put("latest_score", TrinetraCommon.mapOf("score", "70"));
        TrinetraCommon.writeJsonFile(TrinetraCommon.sessionBrainState(name2), st);

        for (String code : List.of("T-001", "T-002", "T-003")) {
            Map<String, Object> r = TrinetraStat.statRun(code, name2, "10.0.0.2");
            expect(r != null, "statRun " + code + " returned result");
        }

        List<Map<String, Object>> nr2 = TrinetraSession.getNormalizedResults(name2);
        expect(nr2.size() == 3,
            "normalized_results has 3 entries (got " + nr2.size() + ")");

        TrinetraSession.ChainVerifyResult cv2 = TrinetraSession.verifyChain(name2);
        expect(cv2.intact, "verifyChain intact after 3 sequential runs -> " + cv2);

        // ── (c) parallel statRunAll preserves chain ──────────────
        System.out.println("\n(c) parallel statRunAll preserves chain");
        String name3 = "snr_parallel";
        TrinetraSession.createSession(name3, "10.0.0.3");
        st = TrinetraCommon.readJsonFile(TrinetraCommon.sessionBrainState(name3));
        st.put("state", TrinetraSession.State.BRAIN_UPDATED.value);
        st.put("latest_score", TrinetraCommon.mapOf("score", "60"));
        TrinetraCommon.writeJsonFile(TrinetraCommon.sessionBrainState(name3), st);

        Set<String> selection = new LinkedHashSet<>(List.of("T-001", "T-002", "T-003", "T-004"));
        List<Map<String, Object>> batchResults =
            TrinetraStat.statRunAll(name3, "10.0.0.3", selection, 4, "testuser");
        expect(batchResults.size() == 4,
            "statRunAll executed 4 tests (got " + batchResults.size() + ")");

        List<Map<String, Object>> nr3 = TrinetraSession.getNormalizedResults(name3);
        expect(nr3.size() == 4,
            "normalized_results has 4 entries after parallel run-all (got " + nr3.size() + ")");

        TrinetraSession.ChainVerifyResult cv3 = TrinetraSession.verifyChain(name3);
        expect(cv3.intact,
            "verifyChain intact after parallel statRunAll -> " + cv3);

        // ── (d) confirmed/suspected findings unchanged ────────────
        System.out.println("\n(d) confirmed_findings/suspected_findings unchanged");
        Map<String, Object> brainState = TrinetraCommon.readJsonFile(
            TrinetraCommon.sessionBrainState(name3));
        Object confirmed = brainState.get("confirmed_findings");
        Object suspected = brainState.get("suspected_findings");
        expect(confirmed instanceof List,
            "confirmed_findings is a list");
        expect(suspected instanceof List,
            "suspected_findings is a list");

        // With manual_review_required decision rules, verdicts are MANUAL_REVIEW.
        // confirmed_findings should contain v_codes from SUCCESS runs only.
        // Since all scripts output "output of T-XXX" which doesn't match any
        // pass/fail criteria, verdicts are MANUAL_REVIEW -> not confirmed.
        @SuppressWarnings("unchecked")
        List<String> confirmedList = (List<String>) confirmed;
        @SuppressWarnings("unchecked")
        List<String> suspectedList = (List<String>) suspected;
        expect(confirmedList.isEmpty(),
            "confirmed_findings is empty (all MANUAL_REVIEW) -> " + confirmedList);
        expect(suspectedList.isEmpty(),
            "suspected_findings is empty (all MANUAL_REVIEW) -> " + suspectedList);

        // Verify findings and normalized_results coexist without conflict
        List<Map<String, Object>> findings3 = TrinetraSession.getFindings(name3);
        expect(findings3.size() == 4,
            "findings still has 4 entries (got " + findings3.size() + ")");
        expect(nr3.size() == 4,
            "normalized_results still has 4 entries (got " + nr3.size() + ")");

        // brain state validation passes
        List<String> errors = TrinetraSession.validateBrainState(name3);
        expect(errors.isEmpty(),
            "validateBrainState clean after parallel run" +
            (errors.isEmpty() ? "" : " -> " + errors));

        System.out.println();
        if (failures == 0) {
            System.out.println("[+] TrinetraStatNormalizedResultsTest: all tests passed");
            return;
        }
        System.err.println("[-] TrinetraStatNormalizedResultsTest: " + failures + " failure(s)");
        System.exit(1);
    }

    /** Minimal static map + scripts so the runner has something to run. */
    private static void setupSyntheticEnv(Path root) throws Exception {
        StringBuilder map = new StringBuilder("{\n");
        for (int i = 0; i < CODES.size(); i++) {
            String c = CODES.get(i);
            map.append("  \"").append(c).append("\": {\n")
               .append("    \"name\": \"Synthetic check ").append(c).append("\",\n")
               .append("    \"category\": \"synthetic\",\n")
               .append("    \"tool\": \"builtin\",\n")
               .append("    \"script\": \"").append(c).append(".sh\",\n")
               .append("    \"decision_rule\": {\n")
               .append("      \"method\": \"manual_review_required\",\n")
               .append("      \"pass_criteria\": \"\",\n")
               .append("      \"fail_criteria\": \"\"\n")
               .append("    },\n")
               .append("    \"default_severity\": \"Low\"\n")
               .append("  }").append(i + 1 < CODES.size() ? "," : "").append("\n");
        }
        map.append("}\n");
        Files.writeString(root.resolve("2_static_map.json"), map.toString());
        Files.writeString(root.resolve("3_decision_engine.csv"),
            "code,test_name,category,tool,script,eval_method,pass_criteria,"
            + "fail_criteria,default_severity,fallback_method,requires_external_tool\n");

        Path scripts = root.resolve("stat_scripts");
        Files.createDirectories(scripts);
        for (String c : CODES) {
            Files.writeString(scripts.resolve(c + ".sh"),
                "#!/bin/bash\n"
                + "echo \"output of " + c + "\"\n"
                + "exit 0\n");
        }
    }
}
