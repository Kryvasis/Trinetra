import java.util.*;
import java.util.regex.*;

/**
 * Juniper JUNOS baseline adapter — parses "set system ..." CLI into SecurityBaseline.
 */
public class JuniperBaselineAdapter {

    public static SecurityBaseline parse(String configContent, String rawVendor) {
        SecurityBaseline b = new SecurityBaseline();
        b.vendor = "Juniper";
        b.rawVendor = rawVendor != null ? rawVendor : "Juniper";
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
            boolean isDelete = ll.startsWith("delete ");

            // SSH service
            if (ll.contains("system services ssh")) {
                if (isDelete) {
                    b.managementPlane.sshEnabled = false;
                    b.managementPlane.sshEvidence.clear();
                    b.managementPlane.sshEvidence.add(evidence);
                } else {
                    b.managementPlane.sshEnabled = true;
                    b.managementPlane.sshEvidence.clear();
                    if (ll.contains("protocol-version v1")) {
                        b.managementPlane.sshVersion = "1";
                        b.managementPlane.sshEvidence.add(evidence);
                        b.evidenceLines.add(evidence);
                    } else if (ll.contains("protocol-version v2")) {
                        b.managementPlane.sshVersion = "2";
                        b.managementPlane.sshEvidence.add(evidence);
                    } else {
                        b.managementPlane.sshVersion = "2"; // default v2 when just enabled
                        b.managementPlane.sshEvidence.add(evidence);
                    }
                }
            }

            // Telnet service
            if (ll.contains("system services telnet")) {
                if (isDelete) {
                    b.managementPlane.telnetEnabled = false;
                    b.managementPlane.telnetEvidence.clear();
                    b.managementPlane.telnetEvidence.add(evidence);
                } else {
                    b.managementPlane.telnetEnabled = true;
                    b.managementPlane.telnetEvidence.clear();
                    b.managementPlane.telnetEvidence.add(evidence);
                    b.evidenceLines.add(evidence);
                }
            }

            // HTTP — JUNOS typically via "set system services web-management"
            if (ll.contains("system services web-management") && ll.contains("http")) {
                if (isDelete) {
                    b.managementPlane.httpEnabled = false;
                    b.managementPlane.httpEvidence.clear();
                    b.managementPlane.httpEvidence.add(evidence);
                }
                else {
                    b.managementPlane.httpEnabled = true;
                    b.managementPlane.httpEvidence.clear();
                    b.managementPlane.httpEvidence.add(evidence);
                    b.evidenceLines.add(evidence);
                }
            }

            // Exec timeout — JUNOS idle-timeout
            Matcher mIdle = Pattern.compile("idle-timeout\\s+(\\d+)", Pattern.CASE_INSENSITIVE).matcher(line);
            if (mIdle.find()) {
                b.managementPlane.execTimeout = mIdle.group(1);
                b.managementPlane.execTimeoutEvidence.clear();
                b.managementPlane.execTimeoutEvidence.add(evidence);
                if ("0".equals(mIdle.group(1))) {
                    b.evidenceLines.add(evidence);
                }
            }

            // Source route — JUNOS: system internet-options no-source-route
            if (ll.contains("no-source-route")) {
                b.managementPlane.sourceRouteEnabled = false;
                b.managementPlane.sourceRouteEvidence.clear();
                b.managementPlane.sourceRouteEvidence.add(evidence);
            } else if (ll.contains("source-route") && !isDelete) {
                b.managementPlane.sourceRouteEnabled = true;
                b.managementPlane.sourceRouteEvidence.clear();
                b.managementPlane.sourceRouteEvidence.add(evidence);
            }

            // Login / users
            Matcher mUser = Pattern.compile("(?i)set\\s+system\\s+login\\s+user\\s+(\\S+)\\s+.*").matcher(line);
            if (mUser.find() && !isDelete) {
                String name = mUser.group(1);
                String authType = "unknown";
                if (ll.contains("plain-text-password")) authType = "plain-text-password";
                else if (ll.contains("encrypted-password") || ll.contains("authentication plain-text-password")) authType = "encrypted-password";
                String priv = null;
                Matcher mClass = Pattern.compile("(?i)class\\s+(\\S+)").matcher(line);
                if (mClass.find()) priv = mClass.group(1);
                SecurityBaseline.Authentication.User u = new SecurityBaseline.Authentication.User();
                u.name = name;
                u.authType = authType;
                u.privilege = priv != null ? priv : "";
                u.evidence.add(evidence);
                b.authentication.users.add(u);
                if (authType.equals("plain-text-password")) b.evidenceLines.add(evidence);
            }

            // SNMP
            Matcher mSnmp = Pattern.compile("(?i)set\\s+snmp\\s+community\\s+(\\S+)\\s+.*").matcher(line);
            if (mSnmp.find() && !isDelete) {
                String comm = mSnmp.group(1);
                SecurityBaseline.Snmp.Community c = new SecurityBaseline.Snmp.Community();
                c.name = comm;
                if ("public".equalsIgnoreCase(comm)) c.classification = "default-public";
                else if ("private".equalsIgnoreCase(comm)) c.classification = "default-private";
                else c.classification = "custom";
                c.evidence.add(evidence);
                b.snmp.communities.add(c);
                if (c.classification.startsWith("default-")) b.evidenceLines.add(evidence);
            }

            // Syslog
            if (ll.contains("set system syslog") && !isDelete) {
                b.logging.enabled = true;
                Matcher mHost = Pattern.compile("set\\s+system\\s+syslog\\s+host\\s+(\\S+)", Pattern.CASE_INSENSITIVE).matcher(line);
                if (mHost.find()) b.logging.hosts.add(mHost.group(1));
                b.logging.evidence.add(evidence);
                b.evidenceLines.add(evidence);
            }
        }

        return b;
    }
}
