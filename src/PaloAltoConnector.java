import java.util.Map;

public class PaloAltoConnector extends GenericSSHConnector {
    @Override
    public String getVendorName() { return "PAN-OS"; }

    @Override
    public void connect(String target, Map<String, String> credentials) {
        super.connect(target, credentials);
    }

    @Override
    public String normalizeCommand(String command) {
        String cmd = command == null ? "" : command.trim();
        if (cmd.equalsIgnoreCase("version")) return "show system info";
        if (cmd.startsWith("show ") && cmd.contains("|")) return cmd;
        return cmd;
    }
}
