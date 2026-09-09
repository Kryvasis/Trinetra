import java.nio.file.*;
import java.util.*;

/**
 * Governed training data model. Active rules can both recognize syntax and
 * update an allow-listed field in the vendor-neutral SecurityBaseline. This
 * keeps runtime training useful without exposing arbitrary reflection or code
 * execution through the rule store.
 *
 * File format:
 * {
 *   "entries": [
     *     {"vendor":"Cisco","pattern":"ip ssh version (\\d+)","v_code":"V-006",
     *      "baseline_field":"management_plane.ssh_version","value":"$1",
     *      "os_version_pattern":"IOS( XE)? 17\\..*","positive_examples":["ip ssh version 2"],
     *      "negative_examples":["logging host 10.0.0.1"],"status":"active"}
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
        public final String vCode;
        public final String baselineField;
        public final String value;
        public final String negatedPattern;
        public final String negatedValue;
        public final String contextPattern;
        public final String osVersionPattern;
        public final int priority;
        public final List<String> positiveExamples;
        public final List<String> negativeExamples;

        public Entry(String vendor, String pattern, String securityCategory, List<String> controlMapping, String remediation, String addedAt) {
            this(vendor, pattern, securityCategory, controlMapping, remediation, addedAt, "");
        }

        public Entry(String vendor, String pattern, String securityCategory, List<String> controlMapping, String remediation, String addedAt, String osVersion) {
            this(vendor, pattern, securityCategory, controlMapping, remediation, addedAt, osVersion,
                "", "", "", "", "", "", "", 0, List.of(), List.of());
        }

        public Entry(String vendor, String pattern, String securityCategory, List<String> controlMapping,
                     String remediation, String addedAt, String osVersion, String vCode,
                     String baselineField, String value, String negatedPattern, String negatedValue,
                     String contextPattern, String osVersionPattern, int priority,
                     List<String> positiveExamples, List<String> negativeExamples) {
            this.vendor = vendor;
            this.pattern = pattern;
            this.securityCategory = securityCategory;
            this.controlMapping = controlMapping != null ? controlMapping : new ArrayList<>();
            this.remediation = remediation;
            this.addedAt = addedAt;
            this.osVersion = osVersion != null ? osVersion : "";
            this.vCode = vCode != null ? vCode : "";
            this.baselineField = baselineField != null ? baselineField : "";
            this.value = value != null ? value : "";
            this.negatedPattern = negatedPattern != null ? negatedPattern : "";
            this.negatedValue = negatedValue != null ? negatedValue : "";
            this.contextPattern = contextPattern != null ? contextPattern : "";
            this.osVersionPattern = osVersionPattern != null ? osVersionPattern : "";
            this.priority = priority;
            this.positiveExamples = positiveExamples != null ? new ArrayList<>(positiveExamples) : new ArrayList<>();
            this.negativeExamples = negativeExamples != null ? new ArrayList<>(negativeExamples) : new ArrayList<>();
        }

        public boolean appliesTo(String candidateVendor, String candidateOs, String context) {
            boolean vendorMatch = vendor.equalsIgnoreCase(candidateVendor)
                || vendor.equalsIgnoreCase("Generic") || vendor.equals("*");
            if (!vendorMatch) return false;
            if (!osVersionPattern.isBlank() && !regexFind(osVersionPattern, candidateOs)) return false;
            return contextPattern.isBlank() || regexFind(contextPattern, context);
        }

        public boolean matches(String line) {
            return regexFind(pattern, line) || (!negatedPattern.isBlank() && regexFind(negatedPattern, line));
        }

        public boolean isNegated(String line) {
            return !negatedPattern.isBlank() && regexFind(negatedPattern, line);
        }

        public String resolvedValue(String line) {
            String template = isNegated(line) ? negatedValue : value;
            String sourcePattern = isNegated(line) ? negatedPattern : pattern;
            if (template == null || template.isBlank()) return template == null ? "" : template;
            try {
                java.util.regex.Matcher matcher = java.util.regex.Pattern.compile(
                    sourcePattern, java.util.regex.Pattern.CASE_INSENSITIVE).matcher(line);
                if (!matcher.find()) return template;
                String resolved = template;
                for (int i = matcher.groupCount(); i >= 1; i--) {
                    resolved = resolved.replace("$" + i, matcher.group(i) == null ? "" : matcher.group(i));
                }
                return resolved;
            } catch (Exception ignored) {
                return template;
            }
        }

        private static boolean regexFind(String expression, String candidate) {
            if (expression == null || expression.isBlank() || candidate == null) return false;
            try {
                return java.util.regex.Pattern.compile(expression,
                    java.util.regex.Pattern.CASE_INSENSITIVE).matcher(candidate).find();
            } catch (Exception ignored) {
                return candidate.toLowerCase(Locale.ROOT).contains(expression.toLowerCase(Locale.ROOT));
            }
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
                    // Governed entries are inert until a second operator approves them.
                    // Legacy entries without a status remain active for compatibility.
                    String status = TrinetraCommon.getString(m, "status", "active");
                    if (!status.equalsIgnoreCase("active")) continue;
                    String vendor = TrinetraCommon.getString(m, "vendor", "");
                    String pattern = TrinetraCommon.getString(m, "pattern", "");
                    String cat = TrinetraCommon.getString(m, "security_category", "");
                    List<String> controls = TrinetraCommon.getStringList(m, "control_mapping");
                    String remediation = TrinetraCommon.getString(m, "remediation", "");
                    String addedAt = TrinetraCommon.getString(m, "added_at", "");
                    String osVersion = TrinetraCommon.getString(m, "os_version", "");
                    String vCode = TrinetraCommon.getString(m, "v_code", "");
                    String baselineField = TrinetraCommon.getString(m, "baseline_field", "");
                    String value = TrinetraCommon.getString(m, "value", "");
                    String negatedPattern = TrinetraCommon.getString(m, "negated_pattern", "");
                    String negatedValue = TrinetraCommon.getString(m, "negated_value", "");
                    String contextPattern = TrinetraCommon.getString(m, "context_pattern", "");
                    String osVersionPattern = TrinetraCommon.getString(m, "os_version_pattern", "");
                    int priority = 0;
                    Object priorityValue = m.get("priority");
                    if (priorityValue instanceof Number) priority = ((Number) priorityValue).intValue();
                    List<String> positiveExamples = TrinetraCommon.getStringList(m, "positive_examples");
                    List<String> negativeExamples = TrinetraCommon.getStringList(m, "negative_examples");
                    if (!vendor.isEmpty() && !pattern.isEmpty()) {
                        out.add(new Entry(vendor, pattern, cat, controls, remediation, addedAt, osVersion,
                            vCode, baselineField, value, negatedPattern, negatedValue, contextPattern,
                            osVersionPattern, priority, positiveExamples, negativeExamples));
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
            if (!e.vCode.isBlank()) m.put("v_code", e.vCode);
            if (!e.baselineField.isBlank()) m.put("baseline_field", e.baselineField);
            if (!e.value.isBlank()) m.put("value", e.value);
            if (!e.negatedPattern.isBlank()) m.put("negated_pattern", e.negatedPattern);
            if (!e.negatedValue.isBlank()) m.put("negated_value", e.negatedValue);
            if (!e.contextPattern.isBlank()) m.put("context_pattern", e.contextPattern);
            if (!e.osVersionPattern.isBlank()) m.put("os_version_pattern", e.osVersionPattern);
            if (e.priority != 0) m.put("priority", e.priority);
            if (!e.positiveExamples.isEmpty()) m.put("positive_examples", e.positiveExamples);
            if (!e.negativeExamples.isEmpty()) m.put("negative_examples", e.negativeExamples);
            list.add(m);
        }
        root.put("entries", list);
        Files.createDirectories(MAP_PATH.getParent());
        TrinetraCommon.writeJsonFile(MAP_PATH, root);
    }

    /** Find first matching training entry for vendor + line (case-insensitive regex). */
    public static Entry findMatch(String vendor, String line) {
        return findMatch(vendor, "", line, "");
    }

    /** Find the highest-priority applicable active rule for vendor, OS and context. */
    public static Entry findMatch(String vendor, String osVersion, String line, String context) {
        if (line == null || line.isBlank()) return null;
        List<Entry> entries = new ArrayList<>(load());
        entries.sort(Comparator.comparingInt((Entry e) -> e.priority).reversed());
        for (Entry e : entries) {
            if (e.appliesTo(vendor, osVersion == null ? "" : osVersion,
                    context == null ? "" : context) && e.matches(line)) return e;
        }
        return null;
    }

    public static void reload() {
        cache = null;
        cacheMtime = 0;
    }
}
