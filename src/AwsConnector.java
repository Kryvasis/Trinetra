import java.util.Map;

public class AwsConnector extends GenericSSHConnector {
    @Override
    public String getVendorName() { return "AWS"; }
    @Override
    public void connect(String target, Map<String, String> credentials) { super.connect(target, credentials); }
    @Override
    public String normalizeCommand(String command) {
        String cmd = command == null ? "" : command.trim();
        if (cmd.equalsIgnoreCase("version")) return "aws --version";
        if (cmd.equalsIgnoreCase("show security-groups")) return "aws ec2 describe-security-groups";
        return cmd;
    }
}
