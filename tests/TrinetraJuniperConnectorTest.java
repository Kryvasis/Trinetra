import java.nio.file.*;
import java.util.*;

/**
 * Tests for Prompt 18: Juniper connector — second vendor via the
 * VendorConnectorRegistry recipe (no core changes).
 *
 * Covers:
 *  (a) Junos command-normalization logic in isolation,
 *  (b) registry resolves "juniper" (any case) to JuniperConnector,
 *  (c) regression: "cisco" still resolves to CiscoConnector,
 *  (d) unknown/blank/"unknown"/unregistered vendors still fall back to
 *      GenericSSHConnector exactly as before the new registration,
 *  (e) end-to-end on a synthetic stat engine: session fingerprinted as
 *      Juniper -> runner injects TRINETRA_VENDOR=Juniper /
 *      TRINETRA_CONNECTOR=JuniperConnector into script env -> findings +
 *      hash-chained normalized_results carry vendor="Juniper" (never
 *      leaking Cisco or defaulting to Generic) -> verifyChain intact ->
 *      deterministic scorer computes expected percentages for this
 *      vendor's results.
 */
public class TrinetraJuniperConnectorTest {

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
        System.out.println("=== TrinetraJuniperConnectorTest ===");
        System.out.println("root: " + root + "\n");

        setupSyntheticEnv(root);

        // ── (a) normalization in isolation ──────────────────────
        System.out.println("(a) Junos command normalization");
        JuniperConnector j = new JuniperConnector();
        expect(j.normalizeCommand(null).isEmpty(), "null passthrough -> empty");
        expect(j.normalizeCommand("show interfaces").equals("show interfaces | no-more"),
            "show command gets '| no-more' pager suppression");
        expect(j.normalizeCommand("show configuration")
                   .equals("show configuration | no-more"),
            "second show command also suppressed (per-command semantics)");
        expect(j.normalizeCommand("show interfaces | match ge-").equals(
                   "show interfaces | match ge-"),
            "existing pipe modifier is not double-appended");
        expect(j.normalizeCommand("version").equals("show version | no-more"),
            "bare 'version' expands to Junos show form and suppresses pager");
        expect(j.normalizeCommand("VERSION").equals("show version | no-more"),
            "noun expansion is case-insensitive");
        expect(j.normalizeCommand("request system reboot").equals("request system reboot"),
            "non-show command passthrough");
        expect(j.normalizeCommand("  show arp  ").equals("show arp | no-more"),
            "surrounding whitespace trimmed before normalization");

        // ── (b) registry resolves the new vendor ────────────────
        System.out.println("\n(b) registry resolves juniper -> JuniperConnector");
        VendorConnector r1 = VendorConnectorRegistry.resolve("juniper");
        expect(r1 instanceof JuniperConnector, "'juniper' -> JuniperConnector");
        expect(VendorConnectorRegistry.resolve("JUNIPER") instanceof JuniperConnector
                   && VendorConnectorRegistry.resolve("Juniper") instanceof JuniperConnector,
            "registry lookup is case-insensitive for juniper");
        expect(r1.getVendorName().equals("Juniper"), "getVendorName == Juniper");
        expect(VendorConnectorRegistry.hasSpecificConnector("juniper"),
            "hasSpecificConnector(juniper) true");
        expect(VendorConnectorRegistry.view().containsKey("juniper"),
            "registry view exposes juniper key");

        // ── (c) Cisco regression ────────────────────────────────
        System.out.println("\n(c) cisco resolution unchanged (no regression)");
        expect(VendorConnectorRegistry.resolve("Cisco") instanceof CiscoConnector,
            "'Cisco' still -> CiscoConnector");
        expect(VendorConnectorRegistry.resolve("cIsCo").getVendorName().equals("Cisco"),
            "case-insensitive cisco lookup unchanged");
        expect(((CiscoConnector) VendorConnectorRegistry.resolve("cisco"))
                   .normalizeCommand("show version")
                   .startsWith("terminal length 0 ; show version"),
            "IOS pager quirk behavior untouched");

        // ── (d) unknown-vendor fallback intact ──────────────────
        System.out.println("\n(d) unknown/blank fallback path unchanged");
        expect(VendorConnectorRegistry.resolve("unknown") instanceof GenericSSHConnector,
            "'unknown' -> generic");
        expect(VendorConnectorRegistry.resolve(null) instanceof GenericSSHConnector,
            "null -> generic");
        expect(VendorConnectorRegistry.resolve("") instanceof GenericSSHConnector,
            "blank -> generic");
        expect(VendorConnectorRegistry.resolve("FrobozzMagic") instanceof GenericSSHConnector,
            "unregistered -> generic");
        expect(!VendorConnectorRegistry.hasSpecificConnector("unknown"),
            "hasSpecificConnector(unknown) false");
        expect(VendorConnectorRegistry.resolve("unknown")
                   .normalizeCommand("show log").equals("show log"),
            "generic dialect still pure passthrough");

        // ── (e) end-to-end on the synthetic stat engine ─────────
        System.out.println("\n(e) e2e: fingerprint->resolve->execute->chain->score");
        TrinetraSession.createSession("vc_juniper", "10.3.0.7");
        // Simulate Iskabon's append_vendor_resolution_to_session output.
        Map<String, Object> sessDoc = TrinetraCommon.readJsonFile(
            TrinetraCommon.sessionJson("vc_juniper"));
        sessDoc.put("vendor_resolution", TrinetraCommon.mapOf(
            "final_vendor", "Juniper",
            "detection_method", "snmp",
            "confidence_score", String.valueOf(0.95)));
        TrinetraCommon.writeJsonFile(TrinetraCommon.sessionJson("vc_juniper"), sessDoc);

        expect(TrinetraSession.getSessionFinalVendor("vc_juniper").equals("Juniper"),
            "getSessionFinalVendor reads Juniper from session JSON");

        List<Map<String, Object>> results =
            TrinetraStat.statRunAll("vc_juniper", "10.3.0.7",
                Set.of("T-901", "T-902"), 1, "tester");
        expect(results.size() == 2, "both selected tests executed");

        String raw1 = rawOutput("vc_juniper", "T-901");
        String raw2 = rawOutput("vc_juniper", "T-902");
        expect(raw1.contains("VENDOR=[Juniper]") && raw2.contains("VENDOR=[Juniper]"),
            "scripts saw TRINETRA_VENDOR=Juniper");
        expect(raw1.contains("CONNECTOR=[JuniperConnector]"),
            "script saw TRINETRA_CONNECTOR=JuniperConnector");
        expect(!raw1.contains("Cisco") && !raw2.contains("Generic]"),
            "no Cisco leakage and no generic fallback in script env");

        List<Map<String, Object>> nr =
            TrinetraSession.getNormalizedResults("vc_juniper");
        expect(nr.size() == 2, "normalized_results has both runs");
        boolean allJuniper = nr.stream().allMatch(
            e -> "Juniper".equals(e.get("vendor")));
        expect(allJuniper, "every normalized_result carries vendor=Juniper");
        Map<String, String> verdicts = new LinkedHashMap<>();
        for (Map<String, Object> e : nr)
            verdicts.put((String) e.get("test_id"), (String) e.get("normalized_result"));
        expect("pass".equals(verdicts.get("T-901")) && "fail".equals(verdicts.get("T-902")),
            "verdicts flow through decision engine (T-901 pass, T-902 fail)");

        TrinetraSession.ChainVerifyResult chain =
            TrinetraSession.verifyChain("vc_juniper");
        expect(chain.intact && chain.toString().contains("(2 links)"),
            "hash chain intact after Juniper runs: " + chain);

        // Scorer against the temp manifest: T-901 pass + T-902 fail map to
        // ISO27001[A.5] and SOC2[CC1] alike -> 50.0% per framework.
        TrinetraCompliance.reload();
        Map<String, Object> score = TrinetraComplianceScorer.score("vc_juniper");
        @SuppressWarnings("unchecked")
        Map<String, Object> fws = (Map<String, Object>) score.get("frameworks");
        expect(fws.size() == 2, "two frameworks scored (got " + fws.size() + ")");
        for (String fw : List.of("ISO27001", "SOC2")) {
            @SuppressWarnings("unchecked")
            Map<String, Object> fwScore = (Map<String, Object>) fws.get(fw);
            expect(fwScore != null, fw + " present in scorer output");
            if (fwScore != null) {
                expect(((Number) fwScore.get("compliance_percentage")).doubleValue() == 50.0,
                    fw + " compliance_percentage == 50.0 (one of two passed)");
                expect((int) fwScore.get("tests_passed") == 1
                           && (int) fwScore.get("tests_failed") == 1,
                    fw + " passed/failed == 1/1");
            }
        }
        expect(((List<?>) score.get("unmapped_tests")).isEmpty(),
            "no unmapped tests in fixture");

        System.out.println("\n" + (failures == 0
            ? "[+] TrinetraJuniperConnectorTest: all tests passed"
            : "[-] TrinetraJuniperConnectorTest: " + failures + " FAILURE(S)"));
        if (failures > 0) System.exit(1);
    }

    private static String rawOutput(String session, String code) {
        Path p = TrinetraCommon.sessionDir(session).resolve(code + "_static_raw.txt");
        return TrinetraCommon.readFileIfExists(p);
    }

    /**
     * Synthetic stat engine: two fast scripts whose verdicts are fully
     * deterministic (exit-code driven) plus a two-entry compliance
     * manifest, so scoring expectations are exact.
     */
    private static void setupSyntheticEnv(Path root) throws Exception {
        StringBuilder map = new StringBuilder("{\n");
        List<String> codes = List.of("T-901", "T-902");
        for (int i = 0; i < codes.size(); i++) {
            String c = codes.get(i);
            map.append("  \"").append(c).append("\": {\n")
               .append("    \"name\": \"Juniper probe ").append(c).append("\",\n")
               .append("    \"category\": \"synthetic\",\n")
               .append("    \"tool\": \"builtin\",\n")
               .append("    \"script\": \"").append(c).append(".sh\",\n")
               .append("    \"decision_rule\": {\n")
               .append("      \"method\": \"exit_code_zero\",\n")
               .append("      \"pass_criteria\": \"exit 0\",\n")
               .append("      \"fail_criteria\": \"non-zero\"\n")
               .append("    },\n")
               .append("    \"default_severity\": \"Low\"\n")
               .append("  }").append(i + 1 < codes.size() ? "," : "").append("\n");
        }
        map.append("}\n");
        Files.writeString(root.resolve("2_static_map.json"), map.toString());
        Files.writeString(root.resolve("3_decision_engine.csv"),
            "code,test_name,category,tool,script,eval_method,pass_criteria,"
                + "fail_criteria,default_severity,fallback_method,requires_external_tool\n"
                + "T-901,Juniper probe A,synthetic,builtin,T-901.sh,exit_code_zero,"
                + "exit 0,CONTROL_VIOLATION,Low,manual_review_required,false\n"
                + "T-902,Juniper probe B,synthetic,builtin,T-902.sh,exit_code_zero,"
                + "exit 0,CONTROL_VIOLATION,Low,manual_review_required,false\n");

        Path scripts = root.resolve("stat_scripts");
        Files.createDirectories(scripts);
        Files.writeString(scripts.resolve("T-901.sh"),
            "#!/bin/bash\n"
                + "echo \"T-901 VENDOR=[$TRINETRA_VENDOR] CONNECTOR=[$TRINETRA_CONNECTOR]\"\n"
                + "exit 0\n");
        // Non-zero exit + output matching fail_criteria -> deterministic FAIL
        // (engine cross-checks text before falling back to MANUAL_REVIEW).
        Files.writeString(scripts.resolve("T-902.sh"),
            "#!/bin/bash\n"
                + "echo \"T-902 VENDOR=[$TRINETRA_VENDOR] CONNECTOR=[$TRINETRA_CONNECTOR]\"\n"
                + "echo \"CONTROL_VIOLATION: simulated weak setting detected\"\n"
                + "exit 3\n");

        Path configDir = root.resolve("config");
        Files.createDirectories(configDir);
        Files.writeString(configDir.resolve("compliance_manifest.json"), """
            {
              "T-901": {
                "description": "Juniper probe A",
                "frameworks": {
                  "ISO27001": ["A.5"],
                  "SOC2": ["CC1"]
                }
              },
              "T-902": {
                "description": "Juniper probe B",
                "frameworks": {
                  "ISO27001": ["A.6"],
                  "SOC2": ["CC2"]
                }
              }
            }
            """);
    }
}
