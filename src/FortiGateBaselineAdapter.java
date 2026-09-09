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
        boolean inSystemInterface = false;
        String currentEdit = "";
        Map<String, String> interfaceAccess = new LinkedHashMap<>();
        Map<String, String> interfaceAccessEvidence = new LinkedHashMap<>();
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
                if (ll.contains("system interface")) inSystemInterface = true;
            } else if (ll.startsWith("edit ")) {
                currentEdit = ll.substring(5).replace("\"", "").trim();
            } else if (ll.equals("next")) {
                currentEdit = "";
            } else if (ll.equals("end")) {
                if (!configStack.isEmpty()) {
                    String popped = configStack.pop();
                    if (popped.contains("snmp community")) inSnmpCommunity = false;
                    if (popped.contains("log syslogd")) inSyslog = false;
                    if (popped.contains("system interface")) inSystemInterface = false;
                }
                currentEdit = "";
            }

            // Interface allowaccess — maps to telnet/http/ssh
            if (ll.contains("set allowaccess")) {
                String scope = inSystemInterface && !currentEdit.isBlank()
                    ? currentEdit : "line-" + num;
                interfaceAccess.put(scope, ll);
                interfaceAccessEvidence.put(scope, evidence);
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

        // Aggregate effective per-interface allowaccess directives. Repeated
        // directives in one interface use last-command-wins; one exposed
        // interface still makes the device-level fact insecure.
        if (!interfaceAccess.isEmpty()) {
            boolean telnet = false, http = false, ssh = false, https = false;
            for (Map.Entry<String, String> item : interfaceAccess.entrySet()) {
                String value = item.getValue();
                String ev = interfaceAccessEvidence.get(item.getKey());
                if (value.matches(".*\\btelnet\\b.*")) {
                    telnet = true;
                    b.managementPlane.telnetEvidence.add(ev);
                    b.evidenceLines.add(ev);
                }
                if (value.matches(".*\\bhttp\\b.*")) {
                    http = true;
                    b.managementPlane.httpEvidence.add(ev);
                    b.evidenceLines.add(ev);
                }
                if (value.matches(".*\\bssh\\b.*")) {
                    ssh = true;
                    b.managementPlane.sshEvidence.add(ev);
                }
                if (value.matches(".*\\bhttps\\b.*")) https = true;
            }
            b.managementPlane.telnetEnabled = telnet;
            b.managementPlane.httpEnabled = http;
            b.managementPlane.httpSecureOnly = https && !http;
            b.managementPlane.sshEnabled = ssh;
            if (ssh) b.managementPlane.sshVersion = "2";
            if (!telnet) b.managementPlane.telnetEvidence.addAll(interfaceAccessEvidence.values());
            if (!http) b.managementPlane.httpEvidence.addAll(interfaceAccessEvidence.values());
        }

        return b;
    }

    private static boolean isComment(String line) {
        String t = line.trim();
        return t.startsWith("#") || t.startsWith("!") || t.isEmpty();
    }
}
