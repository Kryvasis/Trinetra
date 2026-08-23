import java.nio.file.*;
import java.util.*;

/**
 * Tests for TrinetraComplianceScorer — deterministic compliance scoring.
 *
 * Verifies:
 *  (a) mapped test_ids produce correct per-framework percentages
 *  (b) only unmapped test_ids produce 0 frameworks scored + full unmapped list
 *  (c) mixed session produces correct partial scoring + correct unmapped list
 *  (d) empty session never crashes or throws
 */
public class TrinetraComplianceScorerTest {

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
        System.out.println("=== TrinetraComplianceScorerTest ===");
        System.out.println("root: " + root + "\n");

        setupEnv(root);

        // ── (a) session with mapped test_ids → correct per-framework percentages ──
        System.out.println("(a) mapped test_ids produce correct per-framework percentages");
        testMappedSession(root);

        // ── (b) session with only unmapped test_ids → 0 frameworks + full unmapped ──
        System.out.println("\n(b) unmapped-only session produces 0 frameworks + full unmapped list");
        testUnmappedOnlySession(root);

        // ── (c) mixed session → partial scoring + correct unmapped list ──
        System.out.println("\n(c) mixed session produces correct partial scoring + unmapped list");
        testMixedSession(root);

        // ── (d) empty session → no crash, no throw ──
        System.out.println("\n(d) empty session never crashes or throws");
        testEmptySession(root);

        System.out.println("\n" + (failures == 0
            ? "[+] TrinetraComplianceScorerTest: all tests passed"
            : "[-] TrinetraComplianceScorerTest: " + failures + " FAILURE(S)"));
        if (failures > 0) System.exit(1);
    }

    @SuppressWarnings("unchecked")
    private static void testMappedSession(Path root) throws Exception {
        String session = "cscore_mapped";
        Path dir = root.resolve("sessions").resolve(session);
        Files.createDirectories(dir);

        // Create a brain state with 3 normalized_results:
        //   V-003 → PASS, V-004 → FAIL, V-006 → PASS
        Map<String, Object> state = new LinkedHashMap<>();
        state.put("session_name", session);
        state.put("target", "10.5.0.1");
        state.put("findings", new ArrayList<>());
        state.put("already_run_v_codes", new ArrayList<>(List.of("V-003", "V-004", "V-006")));
        state.put("confirmed_findings", new ArrayList<>());
        state.put("suspected_findings", new ArrayList<>());

        List<Map<String, Object>> nr = new ArrayList<>();
        nr.add(makeEntry("V-003", "pass"));
        nr.add(makeEntry("V-004", "fail"));
        nr.add(makeEntry("V-006", "pass"));
        state.put("normalized_results", nr);
        state.put("last_updated", TrinetraCommon.nowIso());

        TrinetraCommon.writeJsonFile(
            TrinetraCommon.sessionBrainState(session), state);

        Map<String, Object> result = TrinetraComplianceScorer.score(session);
        expect(result.get("session_name").equals(session),
            "session_name is correct");

        Map<String, Object> frameworks = (Map<String, Object>) result.get("frameworks");
        expect(frameworks.size() > 0, "at least one framework scored (got " + frameworks.size() + ")");

        // V-003 + V-004 + V-006 all map to ISO27001
        Map<String, Object> iso = (Map<String, Object>) frameworks.get("ISO27001");
        expect(iso != null, "ISO27001 framework present");
        if (iso != null) {
            expect((int) iso.get("tests_passed") == 2,
                "ISO27001 tests_passed == 2 (V-003 + V-006)");
            expect((int) iso.get("tests_failed") == 1,
                "ISO27001 tests_failed == 1 (V-004)");
            expect((int) iso.get("total_tests_mapped") == 3,
                "ISO27001 total_tests_mapped == 3");
            double pct = (double) iso.get("compliance_percentage");
            expect(Math.abs(pct - 66.7) < 0.5,
                "ISO27001 compliance_percentage == 66.7 (got " + pct + ")");
        }

        // V-003 + V-004 + V-006 all map to PCI-DSS too
        Map<String, Object> pci = (Map<String, Object>) frameworks.get("PCI-DSS");
        expect(pci != null, "PCI-DSS framework present");
        if (pci != null) {
            expect((int) pci.get("tests_passed") == 2,
                "PCI-DSS tests_passed == 2");
            expect((int) pci.get("tests_failed") == 1,
                "PCI-DSS tests_failed == 1");
        }

        List<String> unmapped = (List<String>) result.get("unmapped_tests");
        expect(unmapped.isEmpty(), "no unmapped tests for mapped-only session");

        expect((int) result.get("total_tests_executed") == 3,
            "total_tests_executed == 3");

        // Verify coverage_gaps exist (manifest has more controls than these 3 tests cover)
        if (iso != null) {
            List<String> gaps = (List<String>) iso.get("coverage_gaps");
            expect(gaps != null, "ISO27001 coverage_gaps list present");
            // V-003+V-004+V-006 cover some controls, but not all 8 tests' worth
            expect(gaps.size() > 0,
                "ISO27001 has coverage gaps (got " + gaps.size() + " uncovered controls)");
        }

        // Cleanup
        Files.deleteIfExists(dir.resolve("brain_state_" + session + ".json"));
        Files.deleteIfExists(dir.resolve(session + ".json"));
        Files.deleteIfExists(dir.resolve("compliance_score_" + session + ".json"));
        Files.deleteIfExists(dir);
    }

    @SuppressWarnings("unchecked")
    private static void testUnmappedOnlySession(Path root) throws Exception {
        String session = "cscore_unmapped";
        Path dir = root.resolve("sessions").resolve(session);
        Files.createDirectories(dir);

        // All unmapped: T-101, T-102
        Map<String, Object> state = new LinkedHashMap<>();
        state.put("session_name", session);
        state.put("target", "10.5.0.2");
        state.put("findings", new ArrayList<>());
        state.put("already_run_v_codes", new ArrayList<>(List.of("T-101", "T-102")));
        state.put("confirmed_findings", new ArrayList<>());
        state.put("suspected_findings", new ArrayList<>());

        List<Map<String, Object>> nr = new ArrayList<>();
        nr.add(makeEntry("T-101", "pass"));
        nr.add(makeEntry("T-102", "fail"));
        state.put("normalized_results", nr);
        state.put("last_updated", TrinetraCommon.nowIso());

        TrinetraCommon.writeJsonFile(
            TrinetraCommon.sessionBrainState(session), state);

        Map<String, Object> result = TrinetraComplianceScorer.score(session);
        Map<String, Object> frameworks = (Map<String, Object>) result.get("frameworks");
        expect(frameworks.isEmpty(),
            "no frameworks scored (got " + frameworks.size() + ")");

        List<String> unmapped = (List<String>) result.get("unmapped_tests");
        expect(unmapped.size() == 2,
            "unmapped_tests has 2 entries (got " + unmapped.size() + ")");
        expect(unmapped.contains("T-101") && unmapped.contains("T-102"),
            "unmapped_tests contains T-101 and T-102");

        // Cleanup
        Files.deleteIfExists(dir.resolve("brain_state_" + session + ".json"));
        Files.deleteIfExists(dir.resolve(session + ".json"));
        Files.deleteIfExists(dir.resolve("compliance_score_" + session + ".json"));
        Files.deleteIfExists(dir);
    }

    @SuppressWarnings("unchecked")
    private static void testMixedSession(Path root) throws Exception {
        String session = "cscore_mixed";
        Path dir = root.resolve("sessions").resolve(session);
        Files.createDirectories(dir);

        // V-006 (mapped) → PASS, T-201 (unmapped) → FAIL, V-008 (mapped) → PASS
        Map<String, Object> state = new LinkedHashMap<>();
        state.put("session_name", session);
        state.put("target", "10.5.0.3");
        state.put("findings", new ArrayList<>());
        state.put("already_run_v_codes", new ArrayList<>(List.of("V-006", "T-201", "V-008")));
        state.put("confirmed_findings", new ArrayList<>());
        state.put("suspected_findings", new ArrayList<>());

        List<Map<String, Object>> nr = new ArrayList<>();
        nr.add(makeEntry("V-006", "pass"));
        nr.add(makeEntry("T-201", "fail"));
        nr.add(makeEntry("V-008", "pass"));
        state.put("normalized_results", nr);
        state.put("last_updated", TrinetraCommon.nowIso());

        TrinetraCommon.writeJsonFile(
            TrinetraCommon.sessionBrainState(session), state);

        Map<String, Object> result = TrinetraComplianceScorer.score(session);
        Map<String, Object> frameworks = (Map<String, Object>) result.get("frameworks");
        expect(frameworks.size() > 0,
            "frameworks scored for mixed session (got " + frameworks.size() + ")");

        // V-006 + V-008 both map to SOC2
        Map<String, Object> soc2 = (Map<String, Object>) frameworks.get("SOC2");
        expect(soc2 != null, "SOC2 framework present");
        if (soc2 != null) {
            expect((int) soc2.get("tests_passed") == 2,
                "SOC2 tests_passed == 2 (V-006 + V-008)");
            expect((int) soc2.get("tests_failed") == 0,
                "SOC2 tests_failed == 0");
            double pct = (double) soc2.get("compliance_percentage");
            expect(Math.abs(pct - 100.0) < 0.1,
                "SOC2 compliance_percentage == 100.0 (got " + pct + ")");
        }

        List<String> unmapped = (List<String>) result.get("unmapped_tests");
        expect(unmapped.size() == 1,
            "unmapped_tests has 1 entry (got " + unmapped.size() + ")");
        expect(unmapped.contains("T-201"),
            "unmapped_tests contains T-201");

        // Cleanup
        Files.deleteIfExists(dir.resolve("brain_state_" + session + ".json"));
        Files.deleteIfExists(dir.resolve(session + ".json"));
        Files.deleteIfExists(dir.resolve("compliance_score_" + session + ".json"));
        Files.deleteIfExists(dir);
    }

    @SuppressWarnings("unchecked")
    private static void testEmptySession(Path root) throws Exception {
        String session = "cscore_empty";
        Path dir = root.resolve("sessions").resolve(session);
        Files.createDirectories(dir);

        // Empty session — no normalized_results
        Map<String, Object> state = new LinkedHashMap<>();
        state.put("session_name", session);
        state.put("target", "10.5.0.4");
        state.put("findings", new ArrayList<>());
        state.put("already_run_v_codes", new ArrayList<>());
        state.put("confirmed_findings", new ArrayList<>());
        state.put("suspected_findings", new ArrayList<>());
        state.put("normalized_results", new ArrayList<>());
        state.put("last_updated", TrinetraCommon.nowIso());

        TrinetraCommon.writeJsonFile(
            TrinetraCommon.sessionBrainState(session), state);

        boolean threw = false;
        try {
            Map<String, Object> result = TrinetraComplianceScorer.score(session);
            Map<String, Object> frameworks = (Map<String, Object>) result.get("frameworks");
            expect(frameworks.isEmpty(), "empty session has 0 frameworks");
            expect(result.get("unmapped_tests") instanceof List,
                "unmapped_tests is a list (empty)");
            expect((int) result.get("total_tests_executed") == 0,
                "total_tests_executed == 0");
        } catch (Exception e) {
            threw = true;
            System.err.println("  [FAIL] scorer threw on empty session: " + e);
            failures++;
        }
        expect(!threw, "scorer did not throw on empty session");

        // Cleanup
        Files.deleteIfExists(dir.resolve("brain_state_" + session + ".json"));
        Files.deleteIfExists(dir.resolve(session + ".json"));
        Files.deleteIfExists(dir.resolve("compliance_score_" + session + ".json"));
        Files.deleteIfExists(dir);
    }

    private static Map<String, Object> makeEntry(String testId, String verdict) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("device_id", "10.5.0.1");
        entry.put("vendor", "test");
        entry.put("test_id", testId);
        entry.put("raw_output", "");
        entry.put("normalized_result", verdict);
        entry.put("timestamp", TrinetraCommon.nowIso());
        return entry;
    }

    private static void setupEnv(Path root) throws Exception {
        Files.createDirectories(root.resolve("sessions"));
        // Always write a compliance manifest into the temp root
        // so TrinetraCompliance can find it regardless of trinetra.root
        Path configDir = root.resolve("config");
        Files.createDirectories(configDir);
        String manifest = """
            {
              "V-003": {
                "description": "Open port/unnecessary service detection",
                "frameworks": {
                  "ISO27001": ["A.13.1.1", "A.9.4.1"],
                  "NIST_800-53": ["AC-4", "CM-7"],
                  "PCI-DSS": ["1.2.1"],
                  "SOC2": ["CC6.1", "CC6.6"]
                }
              },
              "V-004": {
                "description": "DNS spoofing resilience",
                "frameworks": {
                  "ISO27001": ["A.13.1.1", "A.9.4.1"],
                  "NIST_800-53": ["AC-4", "SC-7"],
                  "PCI-DSS": ["1.3.4"],
                  "SOC2": ["CC6.1", "CC6.6"]
                }
              },
              "V-006": {
                "description": "Weak TLS/SSL version",
                "frameworks": {
                  "ISO27001": ["A.10.1.1", "A.14.1.2"],
                  "NIST_800-53": ["SC-8", "SC-13"],
                  "PCI-DSS": ["4.1"],
                  "SOC2": ["CC6.1"]
                }
              },
              "V-008": {
                "description": "Expired or self-signed TLS certificate",
                "frameworks": {
                  "ISO27001": ["A.10.1.2"],
                  "NIST_800-53": ["SC-17"],
                  "PCI-DSS": ["4.1"],
                  "SOC2": ["CC6.1"]
                }
              }
            }
            """;
        Files.writeString(configDir.resolve("compliance_manifest.json"), manifest);
        TrinetraCompliance.reload();
    }
}
