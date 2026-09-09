import java.util.*;
import java.util.regex.*;

/**
 * Cisco IOS / IOS-XE / NX-OS baseline adapter — parses CLI text into SecurityBaseline.
 * Handles explicit directive semantics; ignores comments, banners, and "no ..." remediation for insecure detection.
 */
public class CiscoBaselineAdapter {

    public static SecurityBaseline parse(String configContent, String rawVendor) {
        SecurityBaseline b = new SecurityBaseline();
        b.vendor = "Cisco";
        b.rawVendor = rawVendor != null ? rawVendor : "Cisco";
        if (configContent == null || configContent.isBlank()) return b;

        String[] rawLines = configContent.split("\\r?\\n", -1);

        // Pre-scan banner delimiters to exclude — must run before line filtering
        Set<Integer> bannerIgnored = new HashSet<>();
        String delimiter = null;
        for (int i = 0; i < rawLines.length; i++) {
            String t = rawLines[i].trim();
            if (delimiter != null) {
                bannerIgnored.add(i);
                if (t.contains(delimiter)) delimiter = null;
                continue;
            }
            Matcher m = Pattern.compile("(?i)^banner\\s+\\S+\\s+(.+)$").matcher(t);
            if (m.find()) {
                String text = m.group(1);
                String token = text.startsWith("^") && text.length() > 1 ? text.substring(0, 2) : text.substring(0, 1);
                if (!text.substring(token.length()).contains(token)) delimiter = token;
            }
        }

        List<String> lines = new ArrayList<>();
        List<Integer> lineNums = new ArrayList<>();
        for (int i = 0; i < rawLines.length; i++) {
            if (bannerIgnored.contains(i)) continue;
            String t = rawLines[i].trim();
            if (t.isEmpty() || t.startsWith("!") || t.startsWith("#")) continue;
            lines.add(t);
            lineNums.add(i + 1);
        }

        for (int idx = 0; idx < lines.size(); idx++) {
            String line = lines.get(idx);
            int num = lineNums.get(idx);
            String ll = line.toLowerCase(Locale.ROOT);
            String evidence = "L" + num + ": " + line;
            boolean isNo = ll.startsWith("no ");

            // SSH version
            if (ll.matches(".*ip\\s+ssh\\s+version\\s+1\\b.*") && !isNo) {
                b.managementPlane.sshEnabled = true;
                b.managementPlane.sshVersion = "1";
                b.managementPlane.sshEvidence.add(evidence);
                b.evidenceLines.add(evidence);
            } else if (ll.matches(".*ip\\s+ssh\\s+version\\s+2\\b.*") && !isNo) {
                b.managementPlane.sshEnabled = true;
                b.managementPlane.sshVersion = "2";
                b.managementPlane.sshEvidence.add(evidence);
                b.evidenceLines.add(evidence);
            } else if (ll.contains("ip ssh") && !isNo && b.managementPlane.sshEnabled == null) {
                b.managementPlane.sshEnabled = true;
            }

            // Telnet transport
            if (ll.matches(".*transport\\s+input\\s+.*\\btelnet\\b.*") && !isNo) {
                b.managementPlane.telnetEnabled = true;
                b.managementPlane.telnetEvidence.add(evidence);
                b.evidenceLines.add(evidence);
            } else if (ll.contains("transport input ssh") && !ll.contains("telnet")) {
                if (b.managementPlane.telnetEnabled == null) b.managementPlane.telnetEnabled = false;
                b.managementPlane.telnetEvidence.add(evidence);
            }

            // HTTP
            if (ll.matches("^\\s*ip\\s+http\\s+server\\s*$") || ll.matches("^\\s*ip\\s+http\\s+server\\s+.*")) {
                if (isNo) {
                    if (b.managementPlane.httpEnabled == null || b.managementPlane.httpEnabled) {
                        b.managementPlane.httpEnabled = false;
                        b.managementPlane.httpEvidence.add(evidence);
                    }
                } else {
                    b.managementPlane.httpEnabled = true;
                    b.managementPlane.httpEvidence.add(evidence);
                    b.evidenceLines.add(evidence);
                }
            }
            if (ll.contains("ip http secure-server") && !isNo) {
                b.managementPlane.httpSecureOnly = true;
            }

            // Exec timeout
            Matcher mTimeout = Pattern.compile("exec-timeout\\s+(\\d+)\\s+(\\d+)", Pattern.CASE_INSENSITIVE).matcher(line);
            if (mTimeout.find()) {
                b.managementPlane.execTimeout = mTimeout.group(1) + " " + mTimeout.group(2);
                b.managementPlane.execTimeoutEvidence.add(evidence);
            }

            // Source route
            if (ll.matches("^\\s*ip\\s+source-route\\s*$")) {
                if (isNo) {
                    b.managementPlane.sourceRouteEnabled = false;
                    b.managementPlane.sourceRouteEvidence.add(evidence);
                } else {
                    b.managementPlane.sourceRouteEnabled = true;
                    b.managementPlane.sourceRouteEvidence.add(evidence);
                }
            }

            // AAA new-model
            if (ll.matches(".*aaa\\s+new-model\\b.*")) {
                if (isNo) {
                    b.authentication.aaaEnabled = false;
                } else {
                    b.authentication.aaaEnabled = true;
                    b.authentication.aaaEvidence.add(evidence);
                }
            }

            // Enable secret / password
            if (ll.matches(".*enable\\s+secret\\b.*") && !isNo) {
                b.authentication.hasEnableSecret = true;
                b.authentication.enableSecretEvidence.add(evidence);
                b.evidenceLines.add(evidence);
            }
            if (ll.matches("\\s*enable\\s+password\\b.*") && !isNo) {
                b.authentication.hasEnablePassword = true;
                b.authentication.enablePasswordEvidence.add(evidence);
                b.evidenceLines.add(evidence);
            }

            // Service password-encryption
            if (ll.matches(".*service\\s+password-encryption\\b.*")) {
                if (isNo) b.authentication.passwordEncryptionEnabled = false;
                else {
                    b.authentication.passwordEncryptionEnabled = true;
                    b.authentication.passwordEncryptionEvidence.add(evidence);
                }
            }

            // Username parsing
            Matcher mUser = Pattern.compile("(?i)^username\\s+(\\S+)\\s+.*").matcher(line);
            if (mUser.find() && !isNo) {
                String name = mUser.group(1);
                String authType = "unknown";
                String priv = null;
                Matcher mPriv = Pattern.compile("(?i)privilege\\s+(\\d+)").matcher(line);
                if (mPriv.find()) priv = mPriv.group(1);
                if (ll.contains(" secret ")) authType = "secret";
                else if (ll.contains(" password ")) authType = "password";
                else if (ll.contains("encrypted-password")) authType = "encrypted-password";
                SecurityBaseline.Authentication.User u = new SecurityBaseline.Authentication.User();
                u.name = name;
                u.authType = authType;
                u.privilege = priv != null ? priv : "";
                u.evidence.add(evidence);
                b.authentication.users.add(u);
                if (authType.equals("password")) b.evidenceLines.add(evidence);
            }

            // SNMP community
            Matcher mSnmp = Pattern.compile("(?i)snmp-server\\s+community\\s+(\\S+)(?:\\s+(\\S+))?.*").matcher(line);
            if (mSnmp.find() && !isNo) {
                String comm = mSnmp.group(1);
                SecurityBaseline.Snmp.Community c = new SecurityBaseline.Snmp.Community();
                c.name = comm;
                if ("public".equalsIgnoreCase(comm)) c.classification = "default-public";
                else if ("private".equalsIgnoreCase(comm)) c.classification = "default-private";
                else c.classification = "custom";
                c.evidence.add(evidence);
                b.snmp.communities.add(c);
                b.snmp.versions.add("2c");
                if (c.classification.startsWith("default-")) b.evidenceLines.add(evidence);
            }

            // Logging
            Matcher mLog = Pattern.compile("(?i)logging\\s+host\\s+(\\S+)").matcher(line);
            if (mLog.find() && !isNo) {
                b.logging.enabled = true;
                b.logging.hosts.add(mLog.group(1));
                b.logging.evidence.add(evidence);
                b.evidenceLines.add(evidence);
            }
            if (ll.matches(".*logging\\s+trap\\b.*") && !isNo) {
                b.logging.enabled = true;
                b.logging.evidence.add(evidence);
            }
            if (ll.matches("^\\s*no\\s+logging\\s+host.*")) {
                b.logging.enabled = false;
                b.logging.evidence.add(evidence);
            }

            // Cryptography — strong vs weak ciphers (CIS 4.1, NIST SC-13)
            // Weak: 3des, des, rc4, md5, null, export
            if (ll.contains("ssh server algorithm encryption") || ll.contains("ssh server algorithm mac") || ll.contains("ssl cipher") || ll.contains("tls cipher")) {
                if (ll.matches(".*(3des|des-cbc|rc4|md5|null|export).*")) {
                    b.cryptography.weakCiphersFound.add(line.trim());
                    b.cryptography.evidence.add(evidence);
                    b.cryptography.strongCryptoEnabled = false;
                    b.evidenceLines.add(evidence);
                }
                if (ll.matches(".*(aes128-ctr|aes256-ctr|aes128-gcm|aes256-gcm|chacha20).*")) {
                    b.cryptography.enabledCiphers.add(line.trim());
                    b.cryptography.evidence.add(evidence);
                    if (b.cryptography.weakCiphersFound.isEmpty()) b.cryptography.strongCryptoEnabled = true;
                }
                // TLS 1.2+
                if (ll.contains("tls1.2") || ll.contains("tls 1.2") || ll.contains("tlsv1.2")) {
                    b.cryptography.tls12OrHigher = true;
                    b.cryptography.tlsEvidence.add(evidence);
                }
            }
            if (ll.contains("ip ssh version 2") && !isNo) {
                b.cryptography.tls12OrHigher = true; // SSHv2 implies strong crypto baseline
                b.cryptography.tlsEvidence.add(evidence);
            }

            // ACLs — granular ACLs (CIS 4.6, NIST AC-4)
            if (ll.matches("(?i)^access-list\\s+\\d+\\s+(permit|deny).*") || ll.matches("(?i)^ip\\s+access-list\\s+.*") || ll.contains("access-group") || ll.contains("access-class")) {
                SecurityBaseline.Acl.AclEntry e = new SecurityBaseline.Acl.AclEntry();
                e.evidence = evidence;
                Matcher mAclName = Pattern.compile("(?i)access-list\\s+(\\S+)").matcher(line);
                if (mAclName.find()) e.name = mAclName.group(1);
                else {
                    Matcher mAcl2 = Pattern.compile("(?i)ip\\s+access-list\\s+\\S+\\s+(\\S+)").matcher(line);
                    if (mAcl2.find()) e.name = mAcl2.group(1);
                    else e.name = "acl";
                }
                e.type = ll.contains("extended") ? "extended" : ll.contains("standard") ? "standard" : "extended";
                e.action = ll.contains("permit") ? "permit" : ll.contains("deny") ? "deny" : "unknown";
                b.acl.entries.add(e);
                b.acl.evidence.add(evidence);
                b.acl.hasGranularAcls = true;
                if (ll.contains("permit ip") && ll.contains("any any") && !isNo) {
                    // Overly permissive — still counts as ACL but flagged
                    b.cryptography.evidence.add(evidence);
                }
            }
        }

        // Defaults where not observed: absence not a pass; leave null/empty
        return b;
    }
}
