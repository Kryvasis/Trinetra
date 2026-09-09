import java.util.*;
import java.util.regex.*;

/**
 * PAN-OS (Palo Alto) baseline adapter — parses "set deviceconfig ..." CLI into SecurityBaseline.
 */
public class PaloAltoBaselineAdapter {

    public static SecurityBaseline parse(String configContent, String rawVendor) {
        SecurityBaseline b = new SecurityBaseline();
        b.vendor = "PAN-OS";
        b.rawVendor = rawVendor != null ? rawVendor : "PAN-OS";
        if (configContent == null || configContent.isBlank()) return b;

        String[] rawLines = configContent.split("\\r?\\n", -1);
        List<String> lines = new ArrayList<>();
        List<Integer> lineNums = new ArrayList<>();
        for (int i = 0; i < rawLines.length; i++) {
            String t = rawLines[i].trim();
            if (t.isEmpty() || t.startsWith("#")) continue;
            lines.add(t);
            lineNums.add(i + 1);
        }

        for (int idx = 0; idx < lines.size(); idx++) {
            String line = lines.get(idx);
            int num = lineNums.get(idx);
            String ll = line.toLowerCase(Locale.ROOT);
            String evidence = "L" + num + ": " + line;

            // Services — PAN-OS: set deviceconfig system service disable-telnet yes/no
            if (ll.contains("disable-telnet")) {
                if (ll.contains("yes")) {
                    b.managementPlane.telnetEnabled = false;
                    b.managementPlane.telnetEvidence.add(evidence);
                } else if (ll.contains("no")) {
                    b.managementPlane.telnetEnabled = true;
                    b.managementPlane.telnetEvidence.add(evidence);
                    b.evidenceLines.add(evidence);
                }
            }
            if (ll.contains("disable-http") || ll.contains("service disable-http")) {
                if (ll.contains("yes")) b.managementPlane.httpEnabled = false;
                else if (ll.contains("no")) {
                    b.managementPlane.httpEnabled = true;
                    b.managementPlane.httpEvidence.add(evidence);
                    b.evidenceLines.add(evidence);
                }
            }
            // SSH — PAN-OS enables SSH via management profile
            if (ll.contains("ssh") && (ll.contains("set ") || ll.contains("service"))) {
                // PAN-OS SSH is enabled by default, but check for disable-ssh
                if (ll.contains("disable-ssh yes")) {
                    b.managementPlane.sshEnabled = false;
                } else if (ll.contains("ssh")) {
                    if (b.managementPlane.sshEnabled == null) {
                        b.managementPlane.sshEnabled = true;
                        b.managementPlane.sshVersion = "2";
                        b.managementPlane.sshEvidence.add(evidence);
                    }
                }
            }

            // Idle timeout — PAN-OS: set deviceconfig system idle-timeout 10
            Matcher mIdle = Pattern.compile("(?i)idle-timeout\\s+(\\d+)").matcher(line);
            if (mIdle.find()) {
                b.managementPlane.execTimeout = mIdle.group(1);
                b.managementPlane.execTimeoutEvidence.add(evidence);
                if ("0".equals(mIdle.group(1))) b.evidenceLines.add(evidence);
            }

            // Admin users — set mgt-config users admin password
            Matcher mUser = Pattern.compile("(?i)set\\s+mgt-config\\s+users\\s+(\\S+)\\s+.*").matcher(line);
            if (mUser.find()) {
                String name = mUser.group(1);
                String authType = "unknown";
                if (ll.contains("password")) authType = "password";
                else if (ll.contains("phash")) authType = "encrypted-password";
                SecurityBaseline.Authentication.User u = new SecurityBaseline.Authentication.User();
                u.name = name;
                u.authType = authType;
                u.evidence.add(evidence);
                if (ll.contains("superuser")) u.privilege = "superuser";
                b.authentication.users.add(u);
                if (authType.equals("password")) b.evidenceLines.add(evidence);
            }
            // Alternative PAN-OS: set deviceconfig system login-banner etc not auth

            // SNMP community — PAN-OS: set deviceconfig system snmp-setting access-setting version v2c
            if (ll.contains("snmp") && ll.contains("community")) {
                Matcher mComm = Pattern.compile("(?i)community\\s+(\\S+)").matcher(line);
                if (mComm.find()) {
                    String comm = mComm.group(1).replace("\"", "").trim();
                    SecurityBaseline.Snmp.Community c = new SecurityBaseline.Snmp.Community();
                    c.name = comm;
                    if ("public".equalsIgnoreCase(comm)) c.classification = "default-public";
                    else if ("private".equalsIgnoreCase(comm)) c.classification = "default-private";
                    else c.classification = "custom";
                    c.evidence.add(evidence);
                    b.snmp.communities.add(c);
                    if (c.classification.startsWith("default-")) b.evidenceLines.add(evidence);
                }
            }
            if (ll.contains("snmp") && ll.contains("v2c")) b.snmp.versions.add("2c");
            if (ll.contains("snmp") && ll.contains("v3")) b.snmp.versions.add("3");

            // Syslog — PAN-OS: set log-setting syslog
            if (ll.contains("syslog") && ll.contains("set ")) {
                Matcher mHost = Pattern.compile("(?i)server\\s+(\\S+)").matcher(line);
                if (mHost.find()) {
                    b.logging.enabled = true;
                    b.logging.hosts.add(mHost.group(1));
                    b.logging.evidence.add(evidence);
                    b.evidenceLines.add(evidence);
                } else if (ll.contains("syslog")) {
                    b.logging.enabled = true;
                    b.logging.evidence.add(evidence);
                }
            }
        }

        return b;
    }
}
