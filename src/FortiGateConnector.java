import java.util.Map;

public class FortiGateConnector extends GenericSSHConnector {
    @Override
    public String getVendorName() { return "FortiOS"; }

    @Override
    public void connect(String target, Map<String, String> credentials) {
        super.connect(target, credentials);
    }

    @Override
    public String normalizeCommand(String command) {
        String cmd = command == null ? "" : command.trim();
        if (cmd.equalsIgnoreCase("version")) return "get system status";
        if (cmd.startsWith("show ") && !cmd.contains("get ")) return cmd.replaceFirst("(?i)show", "get");
        return cmd;
    }
}
