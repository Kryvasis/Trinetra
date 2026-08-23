import java.io.*;
import java.nio.file.*;
import java.util.*;

/**
 * Compliance control-mapping manifest loader.
 * Reads config/compliance_manifest.json and provides per-test-ID lookup
 * for framework control references (ISO 27001, NIST 800-53, PCI-DSS, SOC 2).
 *
 * Missing test_ids return an empty mapping (no error) to support incremental
 * manifest growth.
 */
public class TrinetraCompliance {

    public static final Path MANIFEST_PATH =
        Path.of(TrinetraCommon.PROJECT_ROOT, "config", "compliance_manifest.json");

    private static Map<String, Map<String, Object>> manifest = null;

    @SuppressWarnings("unchecked")
    public static synchronized void loadManifest() {
        if (manifest != null) return;
        manifest = new LinkedHashMap<>();

        String content = TrinetraCommon.readFile(MANIFEST_PATH);
        if (content == null || content.isBlank()) {
            TrinetraCommon.logWarn("Compliance manifest not found or empty: " + MANIFEST_PATH);
            return;
        }

        Object parsed = TrinetraJson.parse(content);
        if (!(parsed instanceof Map)) {
            TrinetraCommon.logWarn("Compliance manifest root is not a JSON object");
            return;
        }

        Map<String, Object> root = (Map<String, Object>) parsed;
        for (Map.Entry<String, Object> entry : root.entrySet()) {
            String testId = entry.getKey();
            if (entry.getValue() instanceof Map) {
                manifest.put(testId.toUpperCase(), (Map<String, Object>) entry.getValue());
            }
        }
        TrinetraCommon.logInfo("Loaded " + manifest.size() + " compliance mappings");
    }

    /**
     * Return the full mapping entry for a test_id, or null if not in the manifest.
     * The returned map contains "description" (String) and "frameworks" (Map of
     * framework name -> List of control IDs).
     */
    public static Map<String, Object> getRawMapping(String testId) {
        loadManifest();
        if (testId == null) return null;
        return manifest.get(testId.toUpperCase());
    }

    /**
     * Return the frameworks/control-IDs structure for a test_id.
     * Returns an empty map if the test_id is not in the manifest.
     * Each framework key maps to a List of control-ID strings.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, List<String>> getControlMappings(String testId) {
        Map<String, Object> entry = getRawMapping(testId);
        if (entry == null) return Collections.emptyMap();

        Object fwObj = entry.get("frameworks");
        if (fwObj instanceof Map) {
            Map<String, Object> raw = (Map<String, Object>) fwObj;
            Map<String, List<String>> result = new LinkedHashMap<>();
            for (Map.Entry<String, Object> fw : raw.entrySet()) {
                if (fw.getValue() instanceof List) {
                    List<String> ids = new ArrayList<>();
                    for (Object item : (List<?>) fw.getValue()) {
                        ids.add(item != null ? item.toString() : "");
                    }
                    result.put(fw.getKey(), ids);
                }
            }
            return result;
        }
        return Collections.emptyMap();
    }

    /**
     * Return the description for a test_id, or an empty string if not found.
     */
    public static String getDescription(String testId) {
        Map<String, Object> entry = getRawMapping(testId);
        if (entry == null) return "";
        Object desc = entry.get("description");
        return desc != null ? desc.toString() : "";
    }

    /**
     * Return all test_ids present in the manifest (uppercased).
     */
    public static Set<String> getMappedTestIds() {
        loadManifest();
        return Collections.unmodifiableSet(manifest.keySet());
    }

    /**
     * Return the number of entries in the loaded manifest.
     */
    public static int size() {
        loadManifest();
        return manifest.size();
    }

    /** Reload the manifest from disk (for testing or hot-reload). */
    public static synchronized void reload() {
        manifest = null;
        loadManifest();
    }
}
