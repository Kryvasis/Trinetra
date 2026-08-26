import java.util.Map;

/**
 * Juniper Junos connector — second vendor plugin (Prompt 18).
 *
 * Follows the exact three-step registry recipe: implements VendorConnector
 * by extending GenericSSHConnector, overrides only the dialect hooks it
 * cares about, and is registered once in VendorConnectorRegistry's static
 * block. No core dispatch/resolution/scoring code changes.
 *
 * Quirks modelled (minimal by design):
 *  - Junos pager suppression is PER COMMAND: every "show" command gets the
 *    "| no-more" pipe modifier appended unless it already carries a pipe
 *    (unlike IOS, where "terminal length 0" is sent once per session).
 *  - bare nouns are expanded to Junos operational "show <noun>" form.
 *
 * Fingerprinting surface (upstream, Iskabon — no changes required):
 *  - SSH banner "SSH-2.0-Juniper_Junos_..." -> banner vendor_guess "Juniper"
 *  - TCP/IP stack os_family "junos"         -> stack vendor "Juniper"
 *  - SNMP sysObjectID 1.3.6.1.4.1.2636.*    -> vendor "Juniper", high confidence
 */
public class JuniperConnector extends GenericSSHConnector {

    @Override
    public String getVendorName() { return "Juniper"; }

    @Override
    public String normalizeCommand(String command) {
        String cmd = command == null ? "" : command.trim();
        // Bare noun -> Junos operational form (then flows through the
        // pipe-suppression logic below like any other show command).
        if (cmd.equalsIgnoreCase("version"))
            cmd = "show version";
        // Per-command pager suppression; never double-append a modifier.
        if (cmd.startsWith("show ") && !cmd.contains("|"))
            return cmd + " | no-more";
        return cmd;
    }
}
