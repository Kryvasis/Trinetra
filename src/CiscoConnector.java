import java.util.Map;

/**
 * Proof-of-pattern Cisco IOS connector: demonstrates a vendor plugin
 * overriding only the dialect hooks it cares about.
 *
 * Quirks modelled (minimal by design):
 *  - disable pager before show commands ("terminal length 0")
 *  - bare nouns are expanded to IOS "show <noun>" form
 */
public class CiscoConnector extends GenericSSHConnector {

    private boolean pagerDisabled;

    @Override
    public String getVendorName() { return "Cisco"; }

    @Override
    public void connect(String target, Map<String, String> credentials) {
        super.connect(target, credentials);
        pagerDisabled = false;
    }

    @Override
    public String normalizeCommand(String command) {
        String cmd = command == null ? "" : command.trim();
        if (!pagerDisabled && cmd.startsWith("show ")) {
            // First show command triggers IOS pager suppression.
            pagerDisabled = true;
            return "terminal length 0 ; " + cmd;
        }
        if (cmd.equalsIgnoreCase("version"))
            return "show version";
        return cmd;
    }
}
