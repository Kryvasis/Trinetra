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
        // Register additional vendors here, e.g.:
        //   FACTORIES.put("fortinet", FortinetConnector::new);
    }

    private VendorConnectorRegistry() {}

    /** Runtime plugin hook (same contract as the static table). */
    public static void register(String vendorName,
                                java.util.function.Supplier<VendorConnector> factory) {
        if (vendorName != null && factory != null)
            FACTORIES.put(vendorName.toLowerCase(Locale.ROOT), factory);
    }

    /** Resolve a connector; never returns null — generic is the floor. */
    public static VendorConnector resolve(String finalVendor) {
        String key = finalVendor == null ? "" : finalVendor.trim().toLowerCase(Locale.ROOT);
        if (!key.isEmpty() && !"unknown".equals(key)) {
            var f = FACTORIES.get(key);
            if (f != null) return f.get();
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
