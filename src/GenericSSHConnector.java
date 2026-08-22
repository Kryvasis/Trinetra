import java.util.HashMap;
import java.util.Map;

/**
 * Fallback connector used when a session's vendor_resolution.final_vendor
 * is "unknown" or matches no registered plugin.  Speaks plain SSH via the
 * system ssh binary, so it is usable today without vendor-specific
 * tooling.
 */
public class GenericSSHConnector implements VendorConnector {

    protected String target;
    protected String user;
    protected String password;
    protected boolean connected;

    @Override
    public String getVendorName() { return "Generic"; }

    @Override
    public void connect(String target, Map<String, String> credentials) {
        this.target = target;
        Map<String, String> creds =
            credentials != null ? credentials : new HashMap<>();
        this.user = creds.getOrDefault("user", System.getProperty("user.name"));
        this.password = creds.getOrDefault("password", "");
        this.connected = target != null && !target.isBlank();
    }

    @Override
    public String runCommand(String command) {
        if (!connected)
            return "ERROR: not connected";
        String[] cmd = buildCommand(normalizeCommand(command));
        String[] out = TrinetraCommon.execCommand(30, cmd);
        if (!"0".equals(out[2]))
            return out[0].isBlank() ? "ERROR: " + out[1] : out[0];
        return out[0];
    }

    @Override
    public void disconnect() {
        connected = false;
        target = null;
    }

    /** True between successful connect() and disconnect(). */
    public final boolean isConnected() { return connected; }

    /** SSH argv for one command; vendor plugins may override. */
    protected String[] buildCommand(String normalizedCommand) {
        return new String[]{
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=5",
            "-o", "BatchMode=yes",
            user + "@" + target,
            normalizedCommand
        };
    }
}
