import java.util.Map;

public class SonicConnector extends GenericSSHConnector {
    @Override
    public String getVendorName() { return "SONiC"; }
    @Override
    public void connect(String target, Map<String, String> credentials) { super.connect(target, credentials); }
    @Override
    public String normalizeCommand(String command) {
        String cmd = command == null ? "" : command.trim();
        if (cmd.equalsIgnoreCase("version")) return "show version";
        if (cmd.startsWith("show ") && !cmd.contains("|")) return cmd + " | no-more";
        return cmd;
    }
}
