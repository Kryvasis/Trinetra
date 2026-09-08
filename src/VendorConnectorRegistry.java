import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Plugin registry mapping vendor_resolution.final_vendor (lowercased) to
 * a connector factory.  Falls back to GenericSSHConnector when the vendor
 * is unknown, blank, "unknown", or unregistered.
 *
 * Adding a vendor = implement VendorConnector + register here.  See the
 * interface javadoc for the three-step recipe; core execution code never
 * changes.
 */
public final class VendorConnectorRegistry {

    private static final ConcurrentHashMap<String,
        java.util.function.Supplier<VendorConnector>> FACTORIES =
        new ConcurrentHashMap<>();

    static {
        // Built-in plugins (three-step recipe: implement + register here).
        FACTORIES.put("cisco", CiscoConnector::new);
        FACTORIES.put("juniper", JuniperConnector::new);
        FACTORIES.put("fortios", FortiGateConnector::new);
        FACTORIES.put("fortigate", FortiGateConnector::new);
        FACTORIES.put("fortinet", FortiGateConnector::new);
        FACTORIES.put("pan-os", PaloAltoConnector::new);
        FACTORIES.put("panos", PaloAltoConnector::new);
        FACTORIES.put("paloalto", PaloAltoConnector::new);
        FACTORIES.put("sonic", SonicConnector::new);
        FACTORIES.put("sonic-vs", SonicConnector::new);
        FACTORIES.put("aws", AwsConnector::new);
        FACTORIES.put("amazon", AwsConnector::new);
        FACTORIES.put("cloud", AwsConnector::new);
    }

    private VendorConnectorRegistry() {}

    // Dynamic vendor discovery — load config/vendor_discovery_map.json hot-reload
    private static volatile long lastDiscoveryLoad = 0;
    private static final long DISCOVERY_RELOAD_MS = 2000;

    private static synchronized void ensureDiscoveryLoaded() {
        long now = System.currentTimeMillis();
        if (now - lastDiscoveryLoad < DISCOVERY_RELOAD_MS) return;
        lastDiscoveryLoad = now;
        try {
            java.nio.file.Path p = java.nio.file.Path.of(TrinetraCommon.PROJECT_ROOT, "config", "vendor_discovery_map.json");
            if (!java.nio.file.Files.exists(p)) return;
            String raw = java.nio.file.Files.readString(p);
            Object parsed = TrinetraJson.parse(raw);
            if (!(parsed instanceof Map)) return;
            @SuppressWarnings("unchecked")
            Map<String, Object> m = (Map<String, Object>) parsed;
            Object oidsObj = m.get("oids");
            if (oidsObj instanceof Map) {
                for (Map.Entry<?,?> e : ((Map<?,?>) oidsObj).entrySet()) {
                    String oid = String.valueOf(e.getKey()).trim();
                    String vendor = String.valueOf(e.getValue()).trim();
                    if (oid.startsWith("1.3.6.1.4.1.") && vendor.length() >= 2 && !FACTORIES.containsKey(vendor.toLowerCase(Locale.ROOT))) {
                        String vLower = vendor.toLowerCase(Locale.ROOT);
                        // Auto-register as Generic with vendor-specific name
                        FACTORIES.putIfAbsent(vLower, () -> new GenericSSHConnector() {
                            @Override public String getVendorName() { return vendor; }
                        });
                    }
                }
            }
            Object familiesObj = m.get("os_families");
            if (familiesObj instanceof Map) {
                for (Map.Entry<?,?> e : ((Map<?,?>) familiesObj).entrySet()) {
                    String family = String.valueOf(e.getKey()).trim().toLowerCase(Locale.ROOT);
                    String vendor = String.valueOf(e.getValue()).trim();
                    if (!family.isEmpty() && !family.startsWith("_") && vendor.length() >= 2 && !FACTORIES.containsKey(family)) {
                        FACTORIES.putIfAbsent(family, () -> new GenericSSHConnector() {
                            @Override public String getVendorName() { return vendor; }
                        });
                    }
                    if (!FACTORIES.containsKey(vendor.toLowerCase(Locale.ROOT))) {
                        FACTORIES.putIfAbsent(vendor.toLowerCase(Locale.ROOT), () -> new GenericSSHConnector() {
                            @Override public String getVendorName() { return vendor; }
                        });
                    }
                }
            }
            Object bannerObj = m.get("banner_learned");
            if (bannerObj instanceof Map) {
                for (Map.Entry<?,?> e : ((Map<?,?>) bannerObj).entrySet()) {
                    String bannerVendor = String.valueOf(e.getValue()).trim();
                    if (bannerVendor.length() >= 2 && !FACTORIES.containsKey(bannerVendor.toLowerCase(Locale.ROOT))) {
                        FACTORIES.putIfAbsent(bannerVendor.toLowerCase(Locale.ROOT), () -> new GenericSSHConnector() {
                            @Override public String getVendorName() { return bannerVendor; }
                        });
                    }
                }
            }
        } catch (Exception ignored) {}
    }

    /** Runtime plugin hook (same contract as the static table). */
    public static void register(String vendorName,
                                java.util.function.Supplier<VendorConnector> factory) {
        if (vendorName != null && factory != null)
            FACTORIES.put(vendorName.toLowerCase(Locale.ROOT), factory);
    }

    /** Auto-discover: if vendor not yet known, auto-register as Generic with that name (banner NLP). */
    public static VendorConnector resolveOrAutoDiscover(String finalVendor, String rawBanner) {
        VendorConnector c = resolve(finalVendor);
        if (!"Generic".equals(c.getVendorName()) || finalVendor == null || finalVendor.isBlank() || "unknown".equalsIgnoreCase(finalVendor)) {
            // Try banner NLP extraction for new vendor
            if (rawBanner != null && !rawBanner.isBlank()) {
                String guessed = extractVendorFromBanner(rawBanner);
                if (guessed != null && !guessed.isBlank() && !FACTORIES.containsKey(guessed.toLowerCase(Locale.ROOT))) {
                    String gv = guessed;
                    register(gv, () -> new GenericSSHConnector() {
                        @Override public String getVendorName() { return gv; }
                    });
                    recordBannerLearned(guessed, rawBanner);
                    return resolve(guessed);
                }
            }
            return c;
        }
        return c;
    }

    private static String extractVendorFromBanner(String banner) {
        if (banner == null) return null;
        String s = banner.trim();
        if (s.startsWith("SSH-")) {
            int dash = s.indexOf('-', 4);
            if (dash > 0) {
                String rest = s.substring(dash+1).trim();
                int us = rest.indexOf('_');
                if (us > 0) return rest.substring(0, us).trim();
                int sp = rest.indexOf(' ');
                if (sp > 0) return rest.substring(0, sp).trim();
                return rest.split("[^A-Za-z0-9-]")[0];
            }
        }
        // Fallback: first capitalized word
        String[] toks = s.split("[\\s/(),;:]");
        for (String t : toks) if (t.length()>=3 && Character.isUpperCase(t.charAt(0)) && t.matches("[A-Za-z0-9-]+")) return t;
        return null;
    }

    private static void recordBannerLearned(String vendor, String rawBanner) {
        try {
            java.nio.file.Path p = java.nio.file.Path.of(TrinetraCommon.PROJECT_ROOT, "config", "vendor_discovery_map.json");
            if (!java.nio.file.Files.exists(p)) return;
            String raw = java.nio.file.Files.readString(p);
            Object parsed = TrinetraJson.parse(raw);
            if (!(parsed instanceof Map)) return;
            @SuppressWarnings("unchecked")
            Map<String, Object> m = (Map<String, Object>) parsed;
            Object bannerObj = m.get("banner_learned");
            Map<String, Object> bannerMap;
            if (bannerObj instanceof Map) bannerMap = (Map<String, Object>) bannerObj;
            else { bannerMap = new java.util.LinkedHashMap<>(); m.put("banner_learned", bannerMap); }
            if (!bannerMap.containsKey(vendor)) {
                bannerMap.put(vendor, rawBanner.length()>200 ? rawBanner.substring(0,200) : rawBanner);
                java.nio.file.Files.writeString(p, TrinetraJson.prettyJson(m));
            }
        } catch (Exception ignored) {}
    }

    /** Resolve a connector; never returns null — generic is the floor. */
    public static VendorConnector resolve(String finalVendor) {
        ensureDiscoveryLoaded();
        String key = finalVendor == null ? "" : finalVendor.trim().toLowerCase(Locale.ROOT);
        if (!key.isEmpty() && !"unknown".equals(key)) {
            var f = FACTORIES.get(key);
            if (f != null) return f.get();
        }
        // Auto-discover unknown vendor as Generic with preserved name (for banner case)
        if (!key.isEmpty() && !"unknown".equals(key) && key.length()>=2 && key.matches("[a-z0-9_-]+")) {
            // Return Generic but preserve requested name via anonymous subclass
            String vendorName = finalVendor.trim();
            return new GenericSSHConnector() {
                @Override public String getVendorName() { return vendorName; }
            };
        }
        return new GenericSSHConnector();
    }

    /** True when a vendor-specific plugin exists for this name. */
    public static boolean hasSpecificConnector(String finalVendor) {
        String key = finalVendor == null ? "" : finalVendor.trim().toLowerCase(Locale.ROOT);
        return !key.isEmpty() && !"unknown".equals(key) && FACTORIES.containsKey(key);
    }

    /** Read-only view of registered vendor keys (diagnostics/tests). */
    public static Map<String, java.util.function.Supplier<VendorConnector>> view() {
        return Map.copyOf(FACTORIES);
    }
}
