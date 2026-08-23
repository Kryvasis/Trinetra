import java.nio.file.*;
import java.util.*;

/**
 * Tests for Prompt 14: compliance control-mapping manifest.
 *
 * Verifies:
 *  (a) a known test_id in the manifest returns correct framework mappings,
 *  (b) an unknown test_id returns an empty/unmapped result without error,
 *  (c) the manifest file parses without error and matches expected structure.
 */
public class TrinetraComplianceTest {

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
        System.out.println("=== TrinetraComplianceTest ===");
        System.out.println("root: " + root + "\n");

        setupComplianceManifest(root);

        // ── (a) known test_id returns correct framework mappings ──
        System.out.println("(a) known test_id V-003 returns framework mappings");
        Map<String, List<String>> fw003 = TrinetraCompliance.getControlMappings("V-003");
        expect(!fw003.isEmpty(), "V-003 has framework mappings");
        expect(fw003.containsKey("ISO27001"), "V-003 has ISO27001 mapping");
        expect(fw003.containsKey("NIST_800-53"), "V-003 has NIST_800-53 mapping");
        expect(fw003.containsKey("PCI-DSS"), "V-003 has PCI-DSS mapping");
        expect(fw003.containsKey("SOC2"), "V-003 has SOC2 mapping");
        expect(fw003.get("ISO27001").contains("A.13.1.1"),
            "V-003 ISO27001 contains A.13.1.1 -> " + fw003.get("ISO27001"));
        expect(fw003.get("PCI-DSS").contains("1.2.1"),
            "V-003 PCI-DSS contains 1.2.1 -> " + fw003.get("PCI-DSS"));
        expect(fw003.get("NIST_800-53").contains("AC-4"),
            "V-003 NIST_800-53 contains AC-4 -> " + fw003.get("NIST_800-53"));

        String desc003 = TrinetraCompliance.getDescription("V-003");
        expect(desc003.equals("Open port/unnecessary service detection"),
            "V-003 description correct -> " + desc003);

        // ── (b) unknown test_id returns empty result without error ──
        System.out.println("\n(b) unknown test_id V-999 returns empty without error");
        Map<String, List<String>> fw999 = TrinetraCompliance.getControlMappings("V-999");
        expect(fw999.isEmpty(), "V-999 returns empty mappings");
        expect(fw999 instanceof Map, "V-999 returns a Map (not null) -> " + fw999.getClass().getSimpleName());

        String desc999 = TrinetraCompliance.getDescription("V-999");
        expect(desc999.isEmpty(), "V-999 returns empty description");

        Map<String, List<String>> fwNull = TrinetraCompliance.getControlMappings(null);
        expect(fwNull.isEmpty(), "null test_id returns empty mappings");

        Map<String, List<String>> fwEmpty = TrinetraCompliance.getControlMappings("");
        expect(fwEmpty.isEmpty(), "empty test_id returns empty mappings");

        // ── (c) manifest file parses correctly and has expected structure ──
        System.out.println("\n(c) manifest file parses correctly and matches expected structure");
        int size = TrinetraCompliance.size();
        expect(size == 8, "manifest contains exactly 8 entries (got " + size + ")");

        Set<String> ids = TrinetraCompliance.getMappedTestIds();
        expect(ids.contains("V-003"), "manifest contains V-003");
        expect(ids.contains("V-006"), "manifest contains V-006");
        expect(ids.contains("V-087"), "manifest contains V-087");
        expect(ids.contains("V-106"), "manifest contains V-106");
        expect(!ids.contains("V-999"), "manifest does not contain V-999");

        // Verify each entry has description + frameworks
        boolean allValid = true;
        for (String id : ids) {
            Map<String, Object> raw = TrinetraCompliance.getRawMapping(id);
            if (raw == null || !raw.containsKey("description") || !raw.containsKey("frameworks")) {
                allValid = false;
                System.err.println("  [FAIL] " + id + " missing description or frameworks");
                failures++;
            }
        }
        expect(allValid, "all entries have 'description' and 'frameworks' keys");

        // Verify JSON file is valid by re-parsing directly
        Path manifestPath = root.resolve("config").resolve("compliance_manifest.json");
        String json = TrinetraCommon.readFile(manifestPath);
        expect(json != null && !json.isBlank(), "manifest file is readable and non-empty");
        Object parsed = TrinetraJson.parse(json);
        expect(parsed instanceof Map, "manifest parses as a JSON object");
        expect(parsed != null && ((Map<?, ?>) parsed).size() == 8,
            "parsed manifest has 8 top-level keys");

        // Verify case-insensitive lookup
        Map<String, List<String>> fwLower = TrinetraCompliance.getControlMappings("v-003");
        expect(!fwLower.isEmpty(), "case-insensitive lookup: 'v-003' finds mappings");

        // ── (d) verify additional V-codes map correctly ──
        System.out.println("\n(d) spot-check additional V-codes");
        Map<String, List<String>> fw006 = TrinetraCompliance.getControlMappings("V-006");
        expect(fw006.containsKey("ISO27001"), "V-006 has ISO27001");
        expect(fw006.get("PCI-DSS").contains("4.1"), "V-006 PCI-DSS contains 4.1");

        Map<String, List<String>> fw057 = TrinetraCompliance.getControlMappings("V-057");
        expect(fw057.get("PCI-DSS").contains("6.5.3"), "V-057 PCI-DSS contains 6.5.3");
        expect(fw057.get("SOC2").contains("CC6.1"), "V-057 SOC2 contains CC6.1");

        Map<String, List<String>> fw087 = TrinetraCompliance.getControlMappings("V-087");
        expect(fw087.containsKey("NIST_800-53"), "V-087 has NIST_800-53");
        expect(fw087.get("NIST_800-53").contains("SA-11"), "V-087 NIST contains SA-11");

        System.out.println("\n[+] TrinetraComplianceTest: " +
            (failures == 0 ? "all tests passed" : failures + " FAILURE(S)"));
        System.exit(failures == 0 ? 0 : 1);
    }

    private static void setupComplianceManifest(Path root) throws Exception {
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
              "V-006": {
                "description": "Weak TLS/SSL version (SSLv3, TLS 1.0, TLS 1.1)",
                "frameworks": {
                  "ISO27001": ["A.10.1.1", "A.14.1.2"],
                  "NIST_800-53": ["SC-8", "SC-13"],
                  "PCI-DSS": ["4.1"],
                  "SOC2": ["CC6.1"]
                }
              },
              "V-007": {
                "description": "Weak cipher suite (NULL, EXPORT, RC4, DES, MD5)",
                "frameworks": {
                  "ISO27001": ["A.10.1.1"],
                  "NIST_800-53": ["SC-13", "SC-12"],
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
              },
              "V-057": {
                "description": "Hardcoded secrets in source or binary",
                "frameworks": {
                  "ISO27001": ["A.10.1.1", "A.9.2.4"],
                  "NIST_800-53": ["AC-6", "IA-5"],
                  "PCI-DSS": ["6.5.3"],
                  "SOC2": ["CC6.1"]
                }
              },
              "V-070": {
                "description": "Unpatched OS / missing security patches",
                "frameworks": {
                  "ISO27001": ["A.12.6.1", "A.14.2.3"],
                  "NIST_800-53": ["SI-2"],
                  "PCI-DSS": ["6.1", "6.2"],
                  "SOC2": ["CC7.1"]
                }
              },
              "V-087": {
                "description": "Vulnerable third-party dependencies (SCA)",
                "frameworks": {
                  "ISO27001": ["A.14.2.3", "A.12.6.1"],
                  "NIST_800-53": ["SA-11", "SI-2"],
                  "PCI-DSS": ["6.3.1", "6.2"],
                  "SOC2": ["CC7.1", "CC8.1"]
                }
              },
              "V-106": {
                "description": "Public cloud storage exposure (S3/GCS/Azure Blob)",
                "frameworks": {
                  "ISO27001": ["A.13.2.1", "A.9.4.1"],
                  "NIST_800-53": ["AC-3", "SC-7"],
                  "PCI-DSS": ["3.4", "7.1.1"],
                  "SOC2": ["CC6.1", "CC6.3"]
                }
              }
            }
            """;
        Files.writeString(configDir.resolve("compliance_manifest.json"), manifest);
    }
}
