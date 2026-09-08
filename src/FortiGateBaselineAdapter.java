import java.util.*;
import java.util.regex.*;

/**
 * FortiOS (Fortinet) baseline adapter — parses FortiGate config into SecurityBaseline.
 * FortiOS syntax: "config system ..." / "set ..." / "end" blocks, allowaccess, admin users.
 */
public class FortiGateBaselineAdapter {

    public static SecurityBaseline parse(String configContent, String rawVendor) {
        SecurityBaseline b = new SecurityBaseline();
        b.vendor = "FortiOS";
        b.rawVendor = rawVendor != null ? rawVendor : "FortiOS";
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

        boolean inSnmpCommunity = false;
        boolean inSyslog = false;
        Deque<String> configStack = new ArrayDeque<>();

        for (int idx = 0; idx < lines.size(); idx++) {
            String line = lines.get(idx);
            int num = lineNums.get(idx);
            String ll = line.toLowerCase(Locale.ROOT);
            String evidence = "L" + num + ": " + line;

            // Track config blocks for FortiOS hierarchical context
            if (ll.startsWith("config ")) {
                configStack.push(ll);
                if (ll.contains("snmp community")) inSnmpCommunity = true;
                if (ll.contains("log syslogd")) inSyslog = true;
            } else if (ll.equals("end") || ll.equals("next")) {
                if (!configStack.isEmpty()) {
                    String popped = configStack.pop();
                    if (popped.contains("snmp community")) inSnmpCommunity = false;
                    if (popped.contains("log syslogd")) inSyslog = false;
                }
                if (ll.equals("end")) { inSnmpCommunity = false; inSyslog = false; configStack.clear(); }
            }

            // Interface allowaccess — maps to telnet/http/ssh
            if (ll.contains("set allowaccess")) {
                if (ll.contains("telnet")) {
                    b.managementPlane.telnetEnabled = true;
                    b.managementPlane.telnetEvidence.add(evidence);
                    b.evidenceLines.add(evidence);
                } else {
                    // Explicit allowaccess without telnet => telnet not enabled (hardened)
                    if (b.managementPlane.telnetEnabled == null) {
                        b.managementPlane.telnetEnabled = false;
                        b.managementPlane.telnetEvidence.add(evidence);
                    }
                }
                // HTTP : check for standalone http token (not https)
                if (ll.matches(".*allowaccess.*\\bhttp\\b.*") && !ll.matches(".*allowaccess.*\\bhttps\\b.*")) {
                    // pure http without https => insecure
                    b.managementPlane.httpEnabled = true;
                    b.managementPlane.httpEvidence.add(evidence);
                    b.evidenceLines.add(evidence);
                } else if (ll.contains("https")) {
                    b.managementPlane.httpSecureOnly = true;
                    if (b.managementPlane.httpEnabled == null) b.managementPlane.httpEnabled = false;
                }
                if (ll.contains("ssh")) {
                    b.managementPlane.sshEnabled = true;
                    b.managementPlane.sshEvidence.add(evidence);
                    if (b.managementPlane.sshVersion == null) b.managementPlane.sshVersion = "2";
                }
            }

            // Config system global — idle timeout
            Matcher mIdle = Pattern.compile("(?i)set\\s+admintimeout\\s+(\\d+)").matcher(line);
            if (mIdle.find()) {
                b.managementPlane.execTimeout = mIdle.group(1);
                b.managementPlane.execTimeoutEvidence.add(evidence);
                if ("0".equals(mIdle.group(1))) b.evidenceLines.add(evidence);
            }

            // Admin users
            Matcher mUser = Pattern.compile("(?i)config\\s+system\\s+admin").matcher(line);
            // FortiOS user block: "edit \"admin\"" followed by set password
            // Simpler: detect "set password" vs presence of "password"
            if (ll.matches(".*edit\\s+\"?\\w+\"?.*") && idx + 3 < lines.size()) {
                // Look ahead for user context is complex; fallback to line-based
            }
            if (ll.contains("set password") || ll.contains("set passwd")) {
                // FortiOS stores encrypted password via set password ENC ...
                SecurityBaseline.Authentication.User u = new SecurityBaseline.Authentication.User();
                u.name = "admin"; // generic, will be refined if edit name captured
                // Detect plain text exposure? FortiOS ENC is encrypted
                if (ll.contains("enc ")) u.authType = "encrypted-password";
                else u.authType = "password";
                u.evidence.add(evidence);
                b.authentication.users.add(u);
            }

            // SNMP community — handle multi-line block: config system snmp community -> edit -> set name
            if (inSnmpCommunity || (ll.contains("snmp") && ll.contains("community"))) {
                Matcher mComm = Pattern.compile("(?i)set\\s+name\\s+(\\S+)").matcher(line);
                if (mComm.find()) {
                    String comm = mComm.group(1).replace("\"", "").trim();
                    // Only treat as SNMP community if inside snmp block or previous block indicates snmp
                    SecurityBaseline.Snmp.Community c = new SecurityBaseline.Snmp.Community();
                    c.name = comm;
                    if ("public".equalsIgnoreCase(comm)) c.classification = "default-public";
                    else if ("private".equalsIgnoreCase(comm)) c.classification = "default-private";
                    else c.classification = "custom";
                    c.evidence.add(evidence);
                    b.snmp.communities.add(c);
                    if (c.classification.startsWith("default-")) b.evidenceLines.add(evidence);
                    b.snmp.versions.add("2c");
                }
            }
            // FortiOS SNMPv3 detection
            if (ll.contains("set snmp") && ll.contains("v3")) {
                b.snmp.versions.add("3");
            }

            // Syslog / logging — handle multi-line: config log syslogd setting -> set server
            if (inSyslog || ll.contains("syslogd")) {
                Matcher mLog = Pattern.compile("(?i)set\\s+server\\s+(\\S+)").matcher(line);
                if (mLog.find()) {
                    b.logging.enabled = true;
                    b.logging.hosts.add(mLog.group(1).replace("\"", ""));
                    b.logging.evidence.add(evidence);
                    b.evidenceLines.add(evidence);
                }
            } else if (ll.contains("log") && ll.contains("server") && !isComment(line)) {
                Matcher mLog2 = Pattern.compile("(?i)set\\s+server\\s+(\\S+)").matcher(line);
                if (mLog2.find() && b.logging.enabled == null) {
                    b.logging.enabled = true;
                    b.logging.hosts.add(mLog2.group(1).replace("\"", ""));
                    b.logging.evidence.add(evidence);
                    b.evidenceLines.add(evidence);
                }
            }
        }

        return b;
    }

    private static boolean isComment(String line) {
        String t = line.trim();
        return t.startsWith("#") || t.startsWith("!") || t.isEmpty();
    }
}
