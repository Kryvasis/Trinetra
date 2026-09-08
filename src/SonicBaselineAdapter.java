import java.util.*;
import java.util.regex.*;

/**
 * SONiC (Software for Open Networking in the Cloud) baseline adapter — White Box networking.
 * Parses SONiC config_db.json style or CLI (config_file shows "sonic-cfggen" or Cisco-like lines via SONiC's FRR).
 * Handles both JSON and CLI variants.
 */
public class SonicBaselineAdapter {

    public static SecurityBaseline parse(String configContent, String rawVendor) {
        SecurityBaseline b = new SecurityBaseline();
        b.vendor = "SONiC";
        b.rawVendor = rawVendor != null ? rawVendor : "SONiC";
        if (configContent == null || configContent.isBlank()) return b;

        String trimmed = configContent.trim();
        // Detect JSON style config_db.json
        if (trimmed.startsWith("{") && trimmed.contains("\"DEVICE_METADATA\"")) {
            return parseJson(configContent, b);
        }
        // Fallback to CLI/FRR style (similar to Cisco but with SONiC markers)
        return parseCli(configContent, b);
    }

    private static SecurityBaseline parseJson(String json, SecurityBaseline b) {
        String ll = json.toLowerCase(Locale.ROOT);
        // SSH
        if (ll.contains("\"ssh\"") || ll.contains("sshd")) {
            b.managementPlane.sshEnabled = true;
            if (ll.contains("version 1") || ll.contains("\"ssh_version\": \"1\"")) {
                b.managementPlane.sshVersion = "1";
                b.managementPlane.sshEvidence.add("JSON: ssh version 1");
            } else {
                b.managementPlane.sshVersion = "2";
                b.managementPlane.sshEvidence.add("JSON: ssh version 2");
            }
        }
        // Telnet
        if (ll.contains("telnet")) {
            b.managementPlane.telnetEnabled = true;
            b.managementPlane.telnetEvidence.add("JSON: telnet enabled");
        }
        // SNMP
        if (ll.contains("snmp")) {
            if (ll.contains("public")) {
                SecurityBaseline.Snmp.Community c = new SecurityBaseline.Snmp.Community();
                c.name = "public"; c.classification = "default-public"; c.evidence.add("JSON: snmp community public");
                b.snmp.communities.add(c);
            }
        }
        // ACL
        if (ll.contains("\"acl\"") || ll.contains("\"acl_table\"")) {
            b.acl.hasGranularAcls = true;
            b.acl.evidence.add("JSON: ACL table present");
            SecurityBaseline.Acl.AclEntry e = new SecurityBaseline.Acl.AclEntry();
            e.name = "sonic_acl"; e.type = "sonic_acl"; e.action = "permit"; e.evidence = "JSON: ACL";
            b.acl.entries.add(e);
        }
        // Logging/syslog
        if (ll.contains("syslog") || ll.contains("logging")) {
            b.logging.enabled = true;
            b.logging.evidence.add("JSON: syslog");
            Matcher m = Pattern.compile("\"server\"\\s*:\\s*\"([^\"]+)\"").matcher(json);
            if (m.find()) b.logging.hosts.add(m.group(1));
        }
        // Crypto
        if (ll.contains("weak") || ll.contains("3des") || ll.contains("rc4")) {
            b.cryptography.weakCiphersFound.add("JSON: weak cipher");
            b.cryptography.strongCryptoEnabled = false;
        }
        if (ll.contains("aes128") || ll.contains("aes256")) {
            b.cryptography.strongCryptoEnabled = true;
            b.cryptography.enabledCiphers.add("JSON: aes");
        }
        return b;
    }

    private static SecurityBaseline parseCli(String configContent, SecurityBaseline b) {
        String[] rawLines = configContent.split("\\r?\\n", -1);
        for (int i = 0; i < rawLines.length; i++) {
            String line = rawLines[i].trim();
            if (line.isEmpty() || line.startsWith("!") || line.startsWith("#")) continue;
            int num = i + 1;
            String ll = line.toLowerCase(Locale.ROOT);
            String evidence = "L" + num + ": " + line;
            boolean isNo = ll.startsWith("no ");

            // Reuse Cisco-like parsing for FRR-based SONiC (vtysh)
            if (ll.matches(".*ip\\s+ssh\\s+version\\s+1.*") && !isNo) {
                b.managementPlane.sshVersion = "1"; b.managementPlane.sshEnabled = true; b.managementPlane.sshEvidence.add(evidence);
            } else if (ll.matches(".*ip\\s+ssh\\s+version\\s+2.*") && !isNo) {
                b.managementPlane.sshVersion = "2"; b.managementPlane.sshEnabled = true; b.managementPlane.sshEvidence.add(evidence);
            }
            if (ll.contains("telnet") && !isNo) { b.managementPlane.telnetEnabled = true; b.managementPlane.telnetEvidence.add(evidence); }
            if (ll.contains("username") && ll.contains("password") && !isNo) {
                SecurityBaseline.Authentication.User u = new SecurityBaseline.Authentication.User();
                u.name = "admin"; u.authType = "password"; u.evidence.add(evidence); b.authentication.users.add(u);
            } else if (ll.contains("username") && ll.contains("secret")) {
                SecurityBaseline.Authentication.User u = new SecurityBaseline.Authentication.User();
                u.name = "admin"; u.authType = "secret"; u.evidence.add(evidence); b.authentication.users.add(u);
            }
            // ACL for SONiC via iptables or ACL table
            if (ll.contains("iptables") || ll.contains("acl") || ll.contains("access-list")) {
                SecurityBaseline.Acl.AclEntry e = new SecurityBaseline.Acl.AclEntry();
                e.name = "sonic_acl"; e.type = "sonic_acl"; e.action = ll.contains("deny") ? "deny" : "permit"; e.evidence = evidence;
                b.acl.entries.add(e); b.acl.hasGranularAcls = true; b.acl.evidence.add(evidence);
            }
            // SNMP
            if (ll.contains("snmp") && ll.contains("community") && ll.contains("public")) {
                SecurityBaseline.Snmp.Community c = new SecurityBaseline.Snmp.Community();
                c.name = "public"; c.classification = "default-public"; c.evidence.add(evidence); b.snmp.communities.add(c);
            }
            // Logging
            if (ll.contains("logging") && ll.contains("host")) {
                Matcher m = Pattern.compile("logging\\s+host\\s+(\\S+)", Pattern.CASE_INSENSITIVE).matcher(line);
                if (m.find()) { b.logging.enabled = true; b.logging.hosts.add(m.group(1)); b.logging.evidence.add(evidence); }
            }
            // Crypto
            if (ll.contains("weak") || ll.contains("3des") || ll.contains("rc4")) {
                b.cryptography.weakCiphersFound.add(line.trim()); b.cryptography.strongCryptoEnabled = false; b.cryptography.evidence.add(evidence);
            }
        }
        return b;
    }
}
