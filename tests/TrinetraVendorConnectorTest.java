import java.nio.file.*;
import java.util.*;

/**
 * Tests for Prompt 13: vendor connector abstraction.
 *
 * Covers:
 *  (a) unknown/blank/"unknown" vendors fall back to GenericSSHConnector,
 *  (b) a known vendor (Cisco) resolves to its specific plugin,
 *  (c) a mock vendor registered at RUNTIME is resolved without touching
 *      any core dispatch code,
 *  (d) dialect hooks: Cisco normalizes commands, generic passes through;
 *      lifecycle connect/disconnect tracked,
 *  (e) end-to-end: stat runner propagates the resolved vendor into the
 *      script environment; session with vendor_resolution=Cisco gets
 *      TRINETRA_VENDOR=Cisco + CiscoConnector, unknown session gets the
 *      generic fallback.
 */
public class TrinetraVendorConnectorTest {

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
        System.out.println("=== TrinetraVendorConnectorTest ===");
        System.out.println("root: " + root + "\n");

        setupSyntheticEnv(root);

        // ── (a) fallback resolution ─────────────────────────────
        System.out.println("(a) unknown/unmatched vendors fall back to generic");
        expect(VendorConnectorRegistry.resolve("unknown")
                   instanceof GenericSSHConnector, "'unknown' -> generic");
        expect(VendorConnectorRegistry.resolve(null)
                   instanceof GenericSSHConnector, "null -> generic");
        expect(VendorConnectorRegistry.resolve("")
                   instanceof GenericSSHConnector, "blank -> generic");
        expect(VendorConnectorRegistry.resolve("FrobozzMagic")
                   instanceof GenericSSHConnector, "unregistered -> generic");

        // ── (b) known vendor resolves to its plugin ─────────────
        System.out.println("\n(b) Cisco resolves to its specific connector");
        VendorConnector cisco = VendorConnectorRegistry.resolve("Cisco");
        expect(cisco instanceof CiscoConnector, "'Cisco' -> CiscoConnector");
        expect(cisco.getVendorName().equals("Cisco"), "getVendorName == Cisco");
        expect(VendorConnectorRegistry.resolve("cIsCo") instanceof CiscoConnector,
            "registry lookup is case-insensitive");
        expect(VendorConnectorRegistry.hasSpecificConnector("Cisco")
               && !VendorConnectorRegistry.hasSpecificConnector("unknown"),
            "hasSpecificConnector reflects registration");

        // ── (c) runtime plugin registration, zero core changes ──
        System.out.println("\n(c) runtime-registered mock connector is used");
        final boolean[] factoryCalled = {false};
        VendorConnectorRegistry.register("MockCorp", () -> {
            factoryCalled[0] = true;
            return new GenericSSHConnector() {
                @Override public String getVendorName() { return "MockCorp"; }
            };
        });
        VendorConnector mock = VendorConnectorRegistry.resolve("mockcorp");
        expect(mock instanceof GenericSSHConnector
               && "MockCorp".equals(mock.getVendorName()),
            "registered at runtime and resolved");
        expect(factoryCalled[0], "factory invoked lazily on resolve");
        // Registry still falls back correctly for others after mutation.
        expect(VendorConnectorRegistry.resolve("StillUnknown")
                   instanceof GenericSSHConnector, "fallback unaffected by new plugin");

        // ── (d) dialect + lifecycle ─────────────────────────────
        System.out.println("\n(d) command normalization and lifecycle");
        cisco.connect("10.0.0.5", Map.of("user", "admin"));
        expect(((GenericSSHConnector) cisco).isConnected(), "connect() marks connected");
        expect(cisco.normalizeCommand("version").equals("show version"),
            "Cisco expands bare 'version' to 'show version'");
        String firstShow = cisco.normalizeCommand("show running-config");
        expect(firstShow.startsWith("terminal length 0 ; show running-config"),
            "Cisco disables pager before first show command");
        expect(cisco.normalizeCommand("reload").equals("reload"),
            "non-show command passthrough");
        VendorConnector generic = VendorConnectorRegistry.resolve("unknown");
        generic.connect("10.0.0.6", null);
        expect(generic.normalizeCommand("show log").equals("show log"),
            "generic normalizeCommand is passthrough");
        cisco.disconnect();
        generic.disconnect();
        expect(!((GenericSSHConnector) cisco).isConnected()
               && !((GenericSSHConnector) generic).isConnected(),
            "disconnect() clears connection state");
        expect(((GenericSSHConnector) cisco).runCommand("x").startsWith("ERROR"),
            "runCommand guarded when disconnected");

        // ── (e) end-to-end env propagation through the stat runner ──
        System.out.println("\n(e) runner injects resolved vendor into script env");
        // Session with explicit Cisco resolution in Trinetra session JSON.
        TrinetraSession.createSession("vc_cisco", "10.2.0.1");
        Map<String, Object> vr = TrinetraCommon.mapOf(
            "final_vendor", "Cisco", "detection_method", "snmp",
            "confidence_score", String.valueOf(0.9));
        Map<String, Object> sessDoc = TrinetraCommon.readJsonFile(
            TrinetraCommon.sessionJson("vc_cisco"));
        sessDoc.put("vendor_resolution", vr);
        TrinetraCommon.writeJsonFile(TrinetraCommon.sessionJson("vc_cisco"), sessDoc);

        expect(TrinetraSession.getSessionFinalVendor("vc_cisco").equals("Cisco"),
            "getSessionFinalVendor reads vendor_resolution from session JSON");

        TrinetraStat.statRunAll("vc_cisco", "10.2.0.1",
            Set.of("T-001"), 1, "tester");
        String raw = rawOutput("vc_cisco", "T-001");
        expect(raw.contains("VENDOR=[Cisco]"), "script saw TRINETRA_VENDOR=Cisco");
        expect(raw.contains("CONNECTOR=[CiscoConnector]"),
            "script saw TRINETRA_CONNECTOR=CiscoConnector");

        // Session with no vendor_resolution anywhere -> generic fallback.
        TrinetraStat.statRunAll("tsel_b_env", "10.2.0.2",
            Set.of("T-002"), 1, "tester");
        expect(TrinetraSession.getSessionFinalVendor("tsel_b_env").equals("unknown"),
            "missing vendor_resolution resolves as 'unknown'");
        String rawB = rawOutput("tsel_b_env", "T-002");
        expect(rawB.contains("VENDOR=[Generic]"), "fallback script env says Generic");
        expect(rawB.contains("CONNECTOR=[GenericSSHConnector]"),
            "fallback script env says GenericSSHConnector");

        System.out.println();
        if (failures == 0) {
            System.out.println("[+] TrinetraVendorConnectorTest: all tests passed");
            return;
        }
        System.err.println("[-] TrinetraVendorConnectorTest: " + failures + " failure(s)");
        System.exit(1);
    }

    private static String rawOutput(String session, String code) {
        Path p = TrinetraCommon.sessionDir(session).resolve(code + "_static_raw.txt");
        return TrinetraCommon.readFileIfExists(p);
    }

    private static void setupSyntheticEnv(Path root) throws Exception {
        StringBuilder map = new StringBuilder("{\n");
        List<String> codes = List.of("T-001", "T-002");
        for (int i = 0; i < codes.size(); i++) {
            String c = codes.get(i);
            map.append("  \"").append(c).append("\": {\n")
               .append("    \"name\": \"Vendor probe ").append(c).append("\",\n")
               .append("    \"category\": \"synthetic\",\n")
               .append("    \"tool\": \"builtin\",\n")
               .append("    \"script\": \"").append(c).append(".sh\",\n")
               .append("    \"decision_rule\": {\n")
               .append("      \"method\": \"manual_review_required\",\n")
               .append("      \"pass_criteria\": \"\",\n")
               .append("      \"fail_criteria\": \"\"\n")
               .append("    },\n")
               .append("    \"default_severity\": \"Low\"\n")
               .append("  }").append(i + 1 < codes.size() ? "," : "").append("\n");
        }
        map.append("}\n");
        Files.writeString(root.resolve("2_static_map.json"), map.toString());
        Files.writeString(root.resolve("3_decision_engine.csv"),
            "code,test_name,category,tool,script,eval_method,pass_criteria,"
            + "fail_criteria,default_severity,fallback_method,requires_external_tool\n");

        Path scripts = root.resolve("stat_scripts");
        Files.createDirectories(scripts);
        for (String c : codes) {
            Files.writeString(scripts.resolve(c + ".sh"),
                "#!/bin/bash\n"
                + "echo \"" + c + " VENDOR=[$TRINETRA_VENDOR] "
                + "CONNECTOR=[$TRINETRA_CONNECTOR]\"\n"
                + "exit 0\n");
        }
    }
}
