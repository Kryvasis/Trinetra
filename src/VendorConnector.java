import java.util.Map;

/**
 * Abstract vendor connector — Prompt 13.
 *
 * Minimal common contract every vendor plugin implements so test
 * execution can dispatch vendor-specific device communication.
 *
 * HOW TO ADD A NEW VENDOR LATER (no core changes required):
 *   1. Implement this interface, e.g.
 *          public class JuniperConnector extends GenericSSHConnector {
 *              @Override public String getVendorName() { return "Juniper"; }
 *              @Override public String normalizeCommand(String cmd) { ... }
 *          }
 *   2. Register it once in VendorConnectorRegistry's static block:
 *          FACTORIES.put("juniper", JuniperConnector::new);
 *      (or at runtime from any plugin loader:
 *          VendorConnectorRegistry.register("Juniper", JuniperConnector::new);)
 *   3. Done. Resolution, fallback to the generic connector, and test
 *      dispatch pick it up automatically — no edits to Trinetra,
 *      TrinetraStat, or TrinetraPen are needed.
 *
 * Lifecycle: connect() -> runCommand()* -> disconnect().
 */
public interface VendorConnector {

    /** Vendor name this connector targets (registry key, case-tolerant). */
    String getVendorName();

    /**
     * Open a management session to the device.  Implementations must not
     * throw on unreachable devices when avoidable; prefer recording state
     * and letting runCommand surface the failure.
     */
    void connect(String target, Map<String, String> credentials);

    /** Run one operational/show command on the device; returns its output. */
    String runCommand(String command);

    /** Close the management session and release resources. */
    void disconnect();

    /**
     * Hook for vendor syntax quirks: translate a generic command into the
     * vendor's CLI dialect before transmission.  Default: passthrough.
     */
    default String normalizeCommand(String command) { return command; }
}
