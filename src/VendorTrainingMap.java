import java.nio.file.*;
import java.util.*;

/**
 * Minimal training data model — JSON file mapping vendor + pattern -> category/control.
 * No code changes required to teach new patterns; just add entries to config/vendor_training_map.json
 * via the Flask training form.
 *
 * File format:
 * {
 *   "entries": [
 *     {"vendor":"Cisco","pattern":"my-custom-feature.*","security_category":"Custom Hardening","control_mapping":["CIS-v8-4.6","CIS-IOS-1.1.1"],"remediation":"no my-custom-feature","added_at":"ISO-8601"}
 *   ]
 * }
 */
public class VendorTrainingMap {

    public static final Path MAP_PATH = Path.of(TrinetraCommon.PROJECT_ROOT, "config", "vendor_training_map.json");

    public static class Entry {
        public final String vendor;
        public final String pattern;
        public final String securityCategory;
        public final List<String> controlMapping;
        public final String remediation;
        public final String addedAt;
        public final String osVersion; // optional metadata — which OS version this pattern was observed on

        public Entry(String vendor, String pattern, String securityCategory, List<String> controlMapping, String remediation, String addedAt) {
            this(vendor, pattern, securityCategory, controlMapping, remediation, addedAt, "");
        }

        public Entry(String vendor, String pattern, String securityCategory, List<String> controlMapping, String remediation, String addedAt, String osVersion) {
            this.vendor = vendor;
            this.pattern = pattern;
            this.securityCategory = securityCategory;
            this.controlMapping = controlMapping != null ? controlMapping : new ArrayList<>();
            this.remediation = remediation;
            this.addedAt = addedAt;
            this.osVersion = osVersion != null ? osVersion : "";
        }
    }

    private static List<Entry> cache = null;
    private static long cacheMtime = 0;

    public static synchronized List<Entry> load() {
        try {
            if (!Files.exists(MAP_PATH)) return new ArrayList<>();
            long mtime = Files.getLastModifiedTime(MAP_PATH).toMillis();
            if (cache != null && mtime == cacheMtime) return cache;
            String content = TrinetraCommon.readFile(MAP_PATH);
            if (content == null || content.isBlank()) {
                cache = new ArrayList<>();
                cacheMtime = mtime;
                return cache;
            }
            Object parsed = TrinetraJson.parse(content);
            if (!(parsed instanceof Map)) {
                cache = new ArrayList<>();
                cacheMtime = mtime;
                return cache;
            }
            Map<String, Object> root = (Map<String, Object>) parsed;
            Object entriesObj = root.get("entries");
            List<Entry> out = new ArrayList<>();
            if (entriesObj instanceof List) {
                for (Object o : (List<?>) entriesObj) {
                    if (!(o instanceof Map)) continue;
                    Map<String, Object> m = (Map<String, Object>) o;
                    String vendor = TrinetraCommon.getString(m, "vendor", "");
                    String pattern = TrinetraCommon.getString(m, "pattern", "");
                    String cat = TrinetraCommon.getString(m, "security_category", "");
                    List<String> controls = TrinetraCommon.getStringList(m, "control_mapping");
                    String remediation = TrinetraCommon.getString(m, "remediation", "");
                    String addedAt = TrinetraCommon.getString(m, "added_at", "");
                    String osVersion = TrinetraCommon.getString(m, "os_version", "");
                    if (!vendor.isEmpty() && !pattern.isEmpty()) {
                        out.add(new Entry(vendor, pattern, cat, controls, remediation, addedAt, osVersion));
                    }
                }
            }
            cache = out;
            cacheMtime = mtime;
            return cache;
        } catch (Exception e) {
            TrinetraCommon.logWarn("VendorTrainingMap load failed: " + e.getMessage());
            return cache != null ? cache : new ArrayList<>();
        }
    }

    public static synchronized boolean addEntry(String vendor, String pattern, String category, List<String> controls, String remediation) {
        try {
            List<Entry> current = new ArrayList<>(load());
            // Avoid duplicates
            for (Entry e : current) {
                if (e.vendor.equalsIgnoreCase(vendor) && e.pattern.equals(pattern)) {
                    return false; // already exists
                }
            }
            current.add(new Entry(vendor, pattern, category, controls, remediation, TrinetraCommon.nowIso()));
            save(current);
            cache = null; // invalidate
            return true;
        } catch (Exception e) {
            TrinetraCommon.logError("Failed to add training entry: " + e.getMessage());
            return false;
        }
    }

    private static void save(List<Entry> entries) throws Exception {
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("_comment", "Vendor training map — no code changes needed to teach new patterns.");
        List<Map<String, Object>> list = new ArrayList<>();
        for (Entry e : entries) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("vendor", e.vendor);
            m.put("pattern", e.pattern);
            m.put("security_category", e.securityCategory);
            m.put("control_mapping", e.controlMapping);
            if (e.remediation != null && !e.remediation.isEmpty()) m.put("remediation", e.remediation);
            m.put("added_at", e.addedAt);
            if (e.osVersion != null && !e.osVersion.isBlank()) m.put("os_version", e.osVersion);
            list.add(m);
        }
        root.put("entries", list);
        Files.createDirectories(MAP_PATH.getParent());
        TrinetraCommon.writeJsonFile(MAP_PATH, root);
    }

    /** Find first matching training entry for vendor + line (case-insensitive regex). */
    public static Entry findMatch(String vendor, String line) {
        if (line == null || line.isBlank()) return null;
        List<Entry> entries = load();
        for (Entry e : entries) {
            if (!e.vendor.equalsIgnoreCase(vendor) && !e.vendor.equalsIgnoreCase("Generic") && !e.vendor.equals("*")) continue;
            try {
                if (line.matches("(?i).*" + e.pattern + ".*") || line.toLowerCase().contains(e.pattern.toLowerCase())) {
                    return e;
                }
                // Also try as regex
                if (java.util.regex.Pattern.compile(e.pattern, java.util.regex.Pattern.CASE_INSENSITIVE).matcher(line).find()) {
                    return e;
                }
            } catch (Exception ex) {
                // Fallback to substring
                if (line.toLowerCase().contains(e.pattern.toLowerCase())) return e;
            }
        }
        return null;
    }

    public static void reload() {
        cache = null;
        cacheMtime = 0;
    }
}
