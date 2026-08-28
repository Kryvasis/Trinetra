import java.nio.file.*;
import java.util.*;

/**
 * Tests for TrinetraAuditReportBuilder — final deliverable audit reports.
 *
 * Run with:
 *   javac -cp out -d out tests/*.java
 *   java -Dtrinetra.root=<temp-root> -cp out:lib/* TrinetraAuditReportBuilderTest
 *
 * Covers:
 *  (a) multi-framework session -> correct per-framework files + combined file
 *      with accurate executive-summary aggregation and full evidence tables,
 *  (b) unmapped-only session -> combined report with zero framework sections
 *      and a complete unmapped-tests appendix, no per-framework files,
 *  (c) executive-summary aggregate equals manual calculation from scorer data,
 *  (d) template-fallback provenance carried visibly into the report
 *      (and a pre-existing LLM narrative keeps its provenance + content),
 *  (e) chain verification status in the appendix matches the actual
 *      TrinetraSession.verifyChain() result — intact AND tampered cases.
 *
 * Also asserts the builder never alters brain state / the hash chain.
 */
public class TrinetraAuditReportBuilderTest {

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
        System.out.println("=== TrinetraAuditReportBuilderTest ===");
        System.out.println("root: " + root + "\n");

        setupEnv(root);
        // Hermetic: force the deterministic template path for generation tests.
        TrinetraNarrativeGenerator.setLlmCall(prompt -> null);

        System.out.println("(a) multi-framework session produces per-framework files "
            + "+ correct combined report");
        testMultiFramework(root);

        System.out.println("\n(b) unmapped-only session -> zero framework sections + "
            + "complete unmapped appendix");
        testUnmappedOnly(root);

        System.out.println("\n(c) aggregate matches manual calculation from scorer data");
        testAggregateMatchesManualCalc(root);

        System.out.println("\n(d) provenance labels: template fallback visible; "
            + "pre-existing LLM narrative preserved");
        testProvenance(root);

        System.out.println("\n(e) appendix chain status matches actual verifyChain() "
            + "(intact + tampered)");
        testChainStatus(root);

        TrinetraNarrativeGenerator.resetLlmCall();
        System.out.println("\n" + (failures == 0
            ? "[+] TrinetraAuditReportBuilderTest: all tests passed"
            : "[-] TrinetraAuditReportBuilderTest: " + failures + " FAILURE(S)"));
        if (failures > 0) System.exit(1);
    }

    // ── (a) ──────────────────────────────────────────────────────────
    @SuppressWarnings("unchecked")
    private static void testMultiFramework(Path root) throws Exception {
        String session = "arb_multi";
        // 5 chained links; verdicts chosen so ISO/NIST/PCI land on 66.7%
        // and SOC2 (which additionally maps V-010) lands on 75.0%.
        seedSession(session,
            entry("V-003", "pass"),
            entry("V-004", "fail"),
            entry("V-006", "pass"),
            entry("V-010", "pass"),
            entry("T-201", "fail"));

        // One real audit-log row so the appendix can carry its uuid.
        TrinetraAudit.beginNewRun();
        String runUuid = TrinetraAudit.currentRunUuid();
        TrinetraAudit.testExecuted("tester", session, "V-003", "pass");

        byte[] before = brainStateBytes(session);
        Map<String, Object> result = TrinetraAuditReportBuilder.buildAuditReport(session);
        byte[] after = brainStateBytes(session);
        expect(result != null, "build returned metadata");
        expect(Arrays.equals(before, after),
            "brain-state file byte-identical after build (no writes)");

        List<String> fwPaths = TrinetraCommon.getStringList(result, "framework_paths");
        expect(fwPaths.size() == 4,
            "four per-framework reports written (got " + fwPaths.size() + ")");
        for (String fw : List.of("ISO27001", "NIST_800-53", "PCI-DSS", "SOC2")) {
            Path p = root.resolve("sessions").resolve(session)
                .resolve("report_" + fw + "_" + session + ".md");
            expect(Files.exists(p), "exists: report_" + fw + "_" + session + ".md");
        }

        String combined = Files.readString(root.resolve("sessions").resolve(session)
            .resolve("audit_report_" + session + ".md"));

        // Executive summary aggregation (see also test (c))
        expect(combined.contains("68.8% average compliance"),
            "combined contains derived aggregate '68.8% average compliance'");
        expect(combined.contains("NOT a scorer-native field"),
            "aggregate clearly labeled as derived, not scorer-native");

        // Per-framework sections appended in sequence with evidence tables
        expect(combined.contains("### ISO 27001"), "combined has ISO 27001 section");
        expect(combined.contains("### NIST 800-53"), "combined has NIST 800-53 section");
        expect(combined.contains("### PCI DSS"), "combined has PCI DSS section");
        expect(combined.contains("### SOC 2"), "combined has SOC 2 section");
        expect(countOccurrences(combined, "| Device |") == 4,
            "evidence table present in each framework section (4 total)");
        expect(combined.contains("arb-device") && combined.contains("TestVendor") && combined.contains("V-003") && combined.contains("pass"),
            "evidence row carries device/vendor/test_id/verdict");
        expect(combined.contains("arb-device") && combined.contains("TestVendor") && combined.contains("V-004") && combined.contains("fail"),
            "failing evidence row present");

        // Unmapped section
        expect(combined.contains("## Unmapped Tests") && combined.contains("T-201"),
            "unmapped-tests section lists T-201");

        // Appendix + tamper evidence + audit uuid linkage
        TrinetraSession.ChainVerifyResult actual = TrinetraSession.verifyChain(session);
        expect(combined.contains(actual.toString()),
            "appendix chain status matches verifyChain(): " + actual);
        expect(combined.contains(runUuid),
            "appendix carries the audit_uuid from trinetra_audit.db");
    }

    // ── (b) ──────────────────────────────────────────────────────────
    private static void testUnmappedOnly(Path root) throws Exception {
        String session = "arb_unmapped";
        seedSession(session, entry("T-101", "pass"), entry("T-102", "fail"));

        Map<String, Object> result = TrinetraAuditReportBuilder.buildAuditReport(session);
        expect(result != null, "build returned metadata");
        if (result == null) return;

        expect(TrinetraCommon.getStringList(result, "framework_paths").isEmpty(),
            "no per-framework files written");
        double agg = ((Number) result.get("derived_aggregate_pct")).doubleValue();
        expect(agg == 0.0, "aggregate is 0.0 when no frameworks scored");

        String combined = Files.readString(Paths.get(
            (String) result.get("combined_path")));
        expect(combined.contains("Zero framework sections"),
            "combined explicitly notes zero framework sections");
        expect(!combined.contains("### ISO 27001") && !combined.contains("### SOC 2"),
            "no per-framework headings present");
        expect(combined.contains("- T-101") && combined.contains("- T-102"),
            "unmapped appendix lists every executed test (T-101, T-102)");
        expect(combined.contains("N/A"), "overall posture reported as N/A");
    }

    // ── (c) ──────────────────────────────────────────────────────────
    @SuppressWarnings("unchecked")
    private static void testAggregateMatchesManualCalc(Path root) throws Exception {
        String session = "arb_multi";   // same fixture as (a)

        Map<String, Object> score = TrinetraCommon.readJsonFile(
            root.resolve("sessions").resolve(session)
                .resolve("compliance_score_" + session + ".json"));
        Map<String, Object> frameworks = (Map<String, Object>) score.get("frameworks");

        // Manual calculation, independent of builder internals:
        // mean of scorer-native compliance_percentage values, rounded to 1 dp.
        double sum = 0;
        for (Object o : frameworks.values()) {
            sum += ((Number) ((Map<String, Object>) o).get("compliance_percentage"))
                .doubleValue();
        }
        double expected = Math.round((sum / frameworks.size()) * 10.0) / 10.0;

        Map<String, Object> result = TrinetraAuditReportBuilder.buildAuditReport(session);
        double got = ((Number) result.get("derived_aggregate_pct")).doubleValue();
        expect(Math.abs(got - expected) < 1e-9,
            "builder aggregate " + got + " == manual calc " + expected);

        // Manual arithmetic cross-check of the fixture itself:
        // ISO/NIST/PCI = 2/3 = 66.7 each; SOC2 = 3/4 = 75.0; mean = 68.775 -> 68.8
        expect(Math.abs(expected - 68.8) < 1e-9,
            "fixture sanity: manual calc equals 68.8 (got " + expected + ")");
    }

    // ── (d) ──────────────────────────────────────────────────────────
    private static void testProvenance(Path root) throws Exception {
        // (d1) generated-with-unavailable-LLM -> TEMPLATE-GENERATED visible
        String tmplSession = "arb_tmpl";
        seedSession(tmplSession, entry("V-003", "pass"));
        Map<String, Object> r1 = TrinetraAuditReportBuilder.buildAuditReport(tmplSession);
        String combined1 = Files.readString(Paths.get((String) r1.get("combined_path")));
        expect(combined1.contains("TEMPLATE-GENERATED"),
            "template provenance label visible in combined report");
        expect(TrinetraNarrativeGenerator.SOURCE_TEMPLATE.equals(r1.get("narrative_source")),
            "result metadata reports template_fallback source");

        // (d2) pre-existing LLM narrative on disk -> reused as-is, LLM provenance
        String preSession = "arb_prellm";
        seedSession(preSession, entry("V-003", "pass"));
        String fakeSection = "### ISO27001\n"
            + "- Compliance posture: ARB-PRELLM-MARKER posture text.\n"
            + "- Failed tests: none.\n";
        String narr = "# Compliance Narrative Report — " + preSession + "\n\n"
            + "| Field | Value |\n|-------|-------|\n"
            + "| **Narrative Source** | Gemini LLM (numbers validated against scorer output) |\n\n"
            + "---\n\n## Framework Narratives\n\n"
            + fakeSection
            + "\n---\n\n## Unmapped Tests\n\nAll executed tests are mapped.\n\n"
            + "_Generated by Trinetra Beta — narrative layer._\n";
        Path narrPath = root.resolve("sessions").resolve(preSession)
            .resolve("compliance_narrative_" + preSession + ".md");
        Files.writeString(narrPath, narr);
        byte[] narrBefore = Files.readAllBytes(narrPath);

        Map<String, Object> r2 = TrinetraAuditReportBuilder.buildAuditReport(preSession);
        expect(TrinetraNarrativeGenerator.SOURCE_LLM.equals(r2.get("narrative_source")),
            "pre-existing non-template narrative detected as LLM source");
        expect(Arrays.equals(narrBefore, Files.readAllBytes(narrPath)),
            "pre-existing narrative file not modified/regenerated");
        String combined2 = Files.readString(Paths.get((String) r2.get("combined_path")));
        expect(combined2.contains("ARB-PRELLM-MARKER"),
            "narrative section extracted into combined report");
        expect(!combined2.contains("TEMPLATE-GENERATED"),
            "no template label when narrative came from the LLM path");
    }

    // ── (e) ──────────────────────────────────────────────────────────
    private static void testChainStatus(Path root) throws Exception {
        // Intact case already covered in (a). Here: tamper -> BROKEN mirrored.
        String session = "arb_tamper";
        seedSession(session,
            entry("V-003", "pass"), entry("V-006", "pass"), entry("V-008", "pass"));

        // Tamper: rewrite verdict of link #1 directly under stored hash.
        Path statePath = TrinetraCommon.sessionBrainState(session);
        Map<String, Object> state = TrinetraCommon.readJsonFile(statePath);
        List<Map<String, Object>> nr = TrinetraCommon.getList(state, "normalized_results");
        nr.get(1).put("normalized_result", "fail");
        state.put("normalized_results", nr);
        TrinetraCommon.writeJsonFile(statePath, state);

        TrinetraSession.ChainVerifyResult actual = TrinetraSession.verifyChain(session);
        expect(!actual.intact && actual.brokenAtIndex == 1,
            "tamper setup valid: chain broken at index 1");

        Map<String, Object> result = TrinetraAuditReportBuilder.buildAuditReport(session);
        String combined = Files.readString(Paths.get((String) result.get("combined_path")));
        expect(combined.contains(actual.toString()),
            "appendix mirrors broken verifyChain(): " + actual);
        expect(combined.contains("Status: BROKEN."),
            "tamper-evidence statement flags BROKEN");
        expect(combined.contains("MUST NOT be trusted"),
            "broken-chain warning present for handover honesty");
    }

    // ── Seeding helpers ──────────────────────────────────────────────

    /** Seed a session whose normalized_results form a REAL hash chain via
     *  TrinetraSession.appendNormalizedResult (the production write path). */
    private static void seedSession(String session, Map<String, Object>... entries)
            throws Exception {
        Path dir = Path.of(System.getProperty("trinetra.root"))
            .resolve("sessions").resolve(session);
        Files.createDirectories(dir);

        Map<String, Object> state = new LinkedHashMap<>();
        state.put("session_name", session);
        state.put("target", "arb-target.example");
        state.put("state", "finding_recorded");
        state.put("last_updated", TrinetraCommon.nowIso());
        state.put("findings", new ArrayList<>());
        state.put("already_run_v_codes", new ArrayList<>());
        state.put("confirmed_findings", new ArrayList<>());
        state.put("suspected_findings", new ArrayList<>());
        state.put("counts", TrinetraCommon.mapOf(
            "total_runs", "0", "success_runs", "0", "failed_runs", "0",
            "unsummarized", "0"));
        state.put("latest_suggestion", null);
        state.put("suggestion_history", new ArrayList<>());
        state.put("latest_score", null);
        TrinetraCommon.writeJsonFile(
            TrinetraCommon.sessionBrainState(session), state);

        for (Map<String, Object> e : entries) {
            boolean ok = TrinetraSession.appendNormalizedResult(session, e);
            if (!ok) throw new IllegalStateException(
                "seed append failed for " + session);
        }
    }

    private static Map<String, Object> entry(String testId, String verdict) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("device_id", "arb-device");
        entry.put("vendor", "TestVendor");
        entry.put("test_id", testId);
        entry.put("raw_output", "raw:" + testId);
        entry.put("normalized_result", verdict);
        entry.put("timestamp", TrinetraCommon.nowIso());
        return entry;
    }

    private static byte[] brainStateBytes(String session) throws Exception {
        return Files.readAllBytes(TrinetraCommon.sessionBrainState(session));
    }

    private static int countOccurrences(String haystack, String needle) {
        int count = 0;
        int idx = 0;
        while ((idx = haystack.indexOf(needle, idx)) >= 0) {
            count++;
            idx += needle.length();
        }
        return count;
    }

    /**
     * Manifest fixture (temp root): V-003/V-004/V-006 map to all four
     * frameworks; V-008 maps to three (no SOC2); V-010 maps to SOC2 only —
     * giving differing per-framework percentages for aggregate testing.
     */
    private static void setupEnv(Path root) throws Exception {
        Files.createDirectories(root.resolve("sessions"));
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
                  "PCI-DSS": ["4.1"]
                }
              },
              "V-010": {
                "description": "Missing HSTS header",
                "frameworks": {
                  "SOC2": ["CC7.1"]
                }
              }
            }
            """;
        Files.writeString(configDir.resolve("compliance_manifest.json"), manifest);
        TrinetraCompliance.reload();
    }
}
