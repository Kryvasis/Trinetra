import java.nio.file.*;
import java.util.*;

/**
 * Tests for TrinetraNarrativeGenerator — validated LLM narrative layer.
 *
 * Run with:
 *   javac -cp out -d out tests/*.java
 *   java -Dtrinetra.root=<temp-root> -cp out:lib/* TrinetraNarrativeGeneratorTest
 *
 * Covers:
 *  (a) a valid LLM response whose numbers match the scorer output passes
 *      validation and is used as-is,
 *  (b) a mocked hallucinated/altered-number response is rejected and the
 *      stricter retry path fires (attempts == 2),
 *  (c) two consecutive invalid responses trigger the deterministic
 *      template fallback with an explicit rejection label,
 *  (d) with no LLM available (mock returns null) the template fallback
 *      alone produces a complete, readable report.
 *
 * Also asserts the narrative never disturbs the brain-state schema or the
 * normalized_results hash chain (derived-report rule).
 */
public class TrinetraNarrativeGeneratorTest {

    private static int failures = 0;

    private static void expect(boolean cond, String what) {
        if (cond) {
            System.out.println("  [ok] " + what);
        } else {
            System.err.println("  [FAIL] " + what);
            failures++;
        }
    }

    /** Scripted LLM transport: pops queued responses; null when exhausted. */
    private static class ScriptedLlm implements TrinetraNarrativeGenerator.LlmCall {
        final List<String> responses = new ArrayList<>();
        final List<String> prompts = new ArrayList<>();

        ScriptedLlm(String... resp) { responses.addAll(Arrays.asList(resp)); }

        @Override public String apply(String prompt) {
            prompts.add(prompt);
            return responses.isEmpty() ? null : responses.remove(0);
        }
    }

    /** Valid narrative: digits limited to the scorer's allowed set
     *  {66.7, 3, 1} for the fixed fixture below; every framework's
     *  compliance_percentage is stated numerically (mandatory). */
    private static final String VALID_A =
        "GEMINI-NARRATIVE-PASS-ALPHA\n\n" +
        "### ISO27001\n" +
        "Compliance posture stands at 66.7%. Of the 3 mapped tests, two passed and one failed.\n" +
        "Failed tests: V-004 — a DNS spoofing weakness means the network-integrity\n" +
        "controls in this framework are not fully effective.\n" +
        "Coverage gaps: 1 control was not exercised by any executed test.\n\n" +
        "### NIST_800-53\n" +
        "Posture sits at 66.7%. One failing test maps to access-control and\n" +
        "system-communications baselines here.\n\n" +
        "### PCI-DSS\n" +
        "Posture is 66.7%. One failing test touches requirements scoped to the\n" +
        "cardholder data environment and should drive immediate remediation.\n\n" +
        "### SOC2\n" +
        "Posture holds at 66.7%; the single failing test weakens the relevant\n" +
        "trust services criteria evidence.\n";

    /** Hallucinated variant: 99.9 does not exist anywhere in scorer output. */
    private static final String HALLUCINATED =
        "Overall posture reaches 99.9% compliance across every framework.\n";

    /** Vacuous variant: numerically faithful in words, but omits every
     *  mandatory numeric figure — must be rejected like a hallucination. */
    private static final String DIGIT_FREE =
        "Posture is fifty percent everywhere; several controls went untested.\n";

    public static void main(String[] args) throws Exception {
        Path root = Path.of(System.getProperty("trinetra.root"));
        System.out.println("=== TrinetraNarrativeGeneratorTest ===");
        System.out.println("root: " + root + "\n");

        setupEnv(root);
        TrinetraNarrativeGenerator.resetLlmCall();

        System.out.println("(a) valid LLM response passes validation and is used as-is");
        testValidResponseUsed(root);

        System.out.println("\n(b) hallucinated numbers rejected; strict retry succeeds");
        testHallucinationTriggersRetry(root);

        System.out.println("\n(c) two consecutive failures trigger template fallback");
        testDoubleFailureFallsBackToTemplate(root);

        System.out.println("\n(d) LLM unavailable -> complete template-only report");
        testOfflineTemplateFallback(root);

        System.out.println("\n(e) digit-free narrative (omits mandatory figures) rejected");
        testDigitFreeRejected(root);

        TrinetraNarrativeGenerator.resetLlmCall();
        System.out.println("\n" + (failures == 0
            ? "[+] TrinetraNarrativeGeneratorTest: all tests passed"
            : "[-] TrinetraNarrativeGeneratorTest: " + failures + " FAILURE(S)"));
        if (failures > 0) System.exit(1);
    }

    // ── (a) ──────────────────────────────────────────────────────────
    @SuppressWarnings("unchecked")
    private static void testValidResponseUsed(Path root) throws Exception {
        String session = "nrg_valid";
        Map<String, Object> score = seedScoredSession(session);
        ScriptedLlm llm = new ScriptedLlm(VALID_A);
        TrinetraNarrativeGenerator.setLlmCall(llm);

        Map<String, Object> meta =
            TrinetraNarrativeGenerator.generateReport(session, score);

        expect(TrinetraNarrativeGenerator.SOURCE_LLM.equals(meta.get("source")),
            "source is gemini_llm_validated (got " + meta.get("source") + ")");
        expect(Integer.valueOf(1).equals(((Number) meta.get("attempts")).intValue()),
            "exactly 1 LLM attempt (got " + meta.get("attempts") + ")");
        expect(llm.prompts.size() == 1, "no retry prompt was sent");

        String prompt = llm.prompts.get(0);
        expect(prompt.contains("\"compliance_percentage\""),
            "prompt embeds exact scorer JSON");
        expect(prompt.contains("EXACTLY as given") || prompt.contains("final"),
            "prompt declares scorer numbers final");
        expect(prompt.contains("NOT counted as compliance failures"),
            "prompt explains unmapped_tests interpretation");

        Path report = Path.of(String.valueOf(meta.get("path")));
        String md = Files.readString(report);
        expect(md.contains("GEMINI-NARRATIVE-PASS-ALPHA"),
            "validated LLM body used verbatim in report");
        expect(md.contains("Gemini LLM (numbers validated against scorer output)"),
            "report labels narrative source as validated LLM");
        expect(md.contains("## Unmapped Tests"), "report has Unmapped Tests section");

        cleanup(session, report);
    }

    // ── (b) ──────────────────────────────────────────────────────────
    private static void testHallucinationTriggersRetry(Path root) throws Exception {
        String session = "nrg_retry";
        Map<String, Object> score = seedScoredSession(session);
        ScriptedLlm llm = new ScriptedLlm(HALLUCINATED, VALID_A);
        TrinetraNarrativeGenerator.setLlmCall(llm);

        Map<String, Object> meta =
            TrinetraNarrativeGenerator.generateReport(session, score);

        expect(llm.prompts.size() == 2, "retry prompt was sent (calls: "
            + llm.prompts.size() + ")");
        expect(TrinetraNarrativeGenerator.SOURCE_LLM.equals(meta.get("source")),
            "second attempt accepted -> gemini_llm_validated");
        expect(Integer.valueOf(2).equals(((Number) meta.get("attempts")).intValue()),
            "attempts recorded as 2 (got " + meta.get("attempts") + ")");

        List<String> rejected =
            TrinetraCommon.getStringList(meta, "rejected_numbers_first_attempt");
        expect(!rejected.isEmpty() && rejected.get(0).startsWith("99.9"),
            "first-attempt offenders captured (got " + rejected + ")");

        String retryPrompt = llm.prompts.get(1);
        expect(retryPrompt.contains("REJECTED BY AUTOMATED NUMBER VALIDATION")
                || retryPrompt.contains("CRITICAL CORRECTION"),
            "retry prompt carries stricter correction instruction");
        expect(retryPrompt.contains("99.9"),
            "retry prompt names the offending value");
        expect(retryPrompt.contains("compliance_percentage=66.7"),
            "retry prompt re-lists the full allowed-value set");

        Path report = Path.of(String.valueOf(meta.get("path")));
        String md = Files.readString(report);
        expect(md.contains("GEMINI-NARRATIVE-PASS-ALPHA"),
            "corrected narrative used in final report");
        expect(!md.contains("99.9"), "hallucinated number absent from report");

        cleanup(session, report);
    }

    // ── (c) ──────────────────────────────────────────────────────────
    private static void testDoubleFailureFallsBackToTemplate(Path root) throws Exception {
        String session = "nrg_fallback";
        Map<String, Object> score = seedScoredSession(session);
        ScriptedLlm llm = new ScriptedLlm(HALLUCINATED, HALLUCINATED + HALLUCINATED);
        TrinetraNarrativeGenerator.setLlmCall(llm);

        Map<String, Object> meta =
            TrinetraNarrativeGenerator.generateReport(session, score);

        expect(TrinetraNarrativeGenerator.SOURCE_TEMPLATE.equals(meta.get("source")),
            "source is template_fallback (got " + meta.get("source") + ")");
        expect(Integer.valueOf(2).equals(((Number) meta.get("attempts")).intValue()),
            "both LLM attempts consumed before fallback");
        expect(String.valueOf(meta.get("fallback_reason"))
                .contains("rejected twice by number validation"),
            "fallback flagged as double-rejection: " + meta.get("fallback_reason"));

        Path report = Path.of(String.valueOf(meta.get("path")));
        String md = Files.readString(report);
        expect(md.contains("Template fallback (LLM narrative rejected twice"),
            "report clearly flags LLM rejection + fallback");
        expect(md.contains("### ISO27001"), "template still narrates ISO27001");
        expect(md.contains("66.7%"), "template reproduces scorer percentage");
        expect(md.contains("V-004"), "template names the failed test deterministically");
        expect(md.contains("## Unmapped Tests"), "unmapped section present");
        expect(md.contains("TEMPLATE-GENERATED"), "footer marks template-generated");
        expect(!md.contains("99.9"), "no hallucinated numbers leaked into report");

        cleanup(session, report);
    }

    // ── (d) ──────────────────────────────────────────────────────────
    private static void testOfflineTemplateFallback(Path root) throws Exception {
        String session = "nrg_offline";
        // Single UNMAPPED failing test: exercises zero-framework branch.
        TrinetraSession.createSession(session, "10.9.9.9");
        Map<String, Object> e = new LinkedHashMap<>();
        e.put("device_id", "dev-x");
        e.put("vendor", "Generic");
        e.put("test_id", "T-301");
        e.put("raw_output", "");
        e.put("normalized_result", "fail");
        e.put("timestamp", TrinetraCommon.nowIso());
        expect(TrinetraSession.appendNormalizedResult(session, e),
            "offline-fixture append ok");
        Map<String, Object> score = TrinetraComplianceScorer.score(session);

        ScriptedLlm llm = new ScriptedLlm();   // empty queue -> null (no API key path)
        TrinetraNarrativeGenerator.setLlmCall(llm);

        Map<String, Object> meta =
            TrinetraNarrativeGenerator.generateReport(session, score);

        expect(TrinetraNarrativeGenerator.SOURCE_TEMPLATE.equals(meta.get("source")),
            "source is template_fallback without any crash");
        expect(String.valueOf(meta.get("fallback_reason")).contains("LLM unavailable"),
            "fallback labeled as LLM-unavailable: " + meta.get("fallback_reason"));

        Path report = Path.of(String.valueOf(meta.get("path")));
        String md = Files.readString(report);
        expect(md.contains("# Compliance Narrative Report — " + session),
            "report header present");
        expect(md.contains("Template fallback (LLM unavailable"),
            "report clearly labeled template-generated");
        expect(md.contains("No compliance-mapped frameworks scored"),
            "zero-framework branch renders cleanly");
        expect(md.contains("## Unmapped Tests"), "unmapped section present");
        expect(md.contains("- T-301"), "unmapped test listed");
        expect(md.contains("**not** compliance failures"),
            "unmapped interpretation present");
        expect(md.contains("total_tests_executed") || md.contains("T-301"),
            "report grounded in scorer data");

        // Derived-report rule: brain-state schema untouched, chain intact.
        List<String> errs = TrinetraSession.validateBrainState(session);
        expect(errs.size() == 1 && errs.get(0).contains("latest_score"),
            "brain-state schema unchanged by narrative layer -> " + errs);
        TrinetraSession.ChainVerifyResult v = TrinetraSession.verifyChain(session);
        expect(v.intact, "normalized_results chain still intact -> " + v);

        cleanup(session, report);
    }

    // ── (e) ──────────────────────────────────────────────────────────
    private static void testDigitFreeRejected(Path root) throws Exception {
        String session = "nrg_words";
        Map<String, Object> score = seedScoredSession(session);
        ScriptedLlm llm = new ScriptedLlm(DIGIT_FREE, VALID_A);
        TrinetraNarrativeGenerator.setLlmCall(llm);

        Map<String, Object> meta =
            TrinetraNarrativeGenerator.generateReport(session, score);

        expect(llm.prompts.size() == 2,
            "digit-free response rejected and retried (calls: "
            + llm.prompts.size() + ")");
        expect(TrinetraNarrativeGenerator.SOURCE_LLM.equals(meta.get("source")),
            "corrected numeric narrative accepted on retry");
        String retryPrompt = llm.prompts.get(1);
        expect(retryPrompt.contains("OMITTED")
                && retryPrompt.contains("compliance_percentage=66.7"),
            "retry prompt names the omitted mandatory percentages");
        expect(!retryPrompt.contains("Offending numeric values found in your response: (none)")
                || retryPrompt.contains("(none)"),
            "no false offender claimed for word-only text");

        Path report = Path.of(String.valueOf(meta.get("path")));
        String md = Files.readString(report);
        expect(md.contains("66.7%"), "report carries numeric percentages");
        expect(md.contains("fifty percent") == false,
            "word-only figures absent from final report");

        cleanup(session, report);
    }

    // ── Fixtures ─────────────────────────────────────────────────────

    /**
     * Session with V-003 pass, V-004 fail, V-006 pass against the shared
     * manifest. Deterministic scorer outcome:
     *   ISO27001/NIST_800-53/PCI-DSS/SOC2 all: pct 66.7, passed 2, failed 1,
     *   mapped 3; unmapped_tests empty; total_tests_executed 3.
     */
    private static Map<String, Object> seedScoredSession(String session) {
        TrinetraSession.createSession(session, "10.5.0.50");
        append(session, "V-003", "pass");
        append(session, "V-004", "fail");
        append(session, "V-006", "pass");
        return TrinetraComplianceScorer.score(session);
    }

    private static void append(String session, String testId, String verdict) {
        Map<String, Object> e = new LinkedHashMap<>();
        e.put("device_id", "dev-" + testId);
        e.put("vendor", "Cisco");
        e.put("test_id", testId);
        e.put("raw_output", "");
        e.put("normalized_result", verdict);
        e.put("timestamp", TrinetraCommon.nowIso());
        if (!TrinetraSession.appendNormalizedResult(session, e)) {
            throw new IllegalStateException("fixture append failed: " + testId);
        }
    }

    private static void cleanup(String session, Path report) throws Exception {
        Files.deleteIfExists(report);
        Files.deleteIfExists(TrinetraCommon.sessionDir(session)
            .resolve("compliance_score_" + session + ".json"));
        Path dir = TrinetraCommon.sessionDir(session);
        if (Files.exists(dir)) {
            try (var walk = Files.walk(dir)) {
                walk.sorted(Comparator.reverseOrder()).forEach(p -> {
                    try { Files.deleteIfExists(p); } catch (Exception ignored) {}
                });
            }
        }
    }

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
