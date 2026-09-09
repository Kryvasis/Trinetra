import java.util.*;
import java.util.regex.*;

/**
 * AWS Cloud-native baseline adapter — parses Security Group / NACL JSON or CLI exports.
 * Handles aws ec2 describe-security-groups JSON and NACL configs.
 */
public class AwsBaselineAdapter {

    public static SecurityBaseline parse(String configContent, String rawVendor) {
        SecurityBaseline b = new SecurityBaseline();
        b.vendor = "AWS";
        b.rawVendor = rawVendor != null ? rawVendor : "AWS";
        if (configContent == null || configContent.isBlank()) return b;

        String trimmed = configContent.trim();
        // Detect AWS JSON (describe-security-groups, NACL, etc.)
        if (trimmed.startsWith("{") && (trimmed.contains("\"SecurityGroups\"") || trimmed.contains("\"NetworkAcls\"") || trimmed.contains("\"GroupId\""))) {
            return parseJson(configContent, b);
        }
        // Fallback to CLI / Terraform style
        return parseCli(configContent, b);
    }

    private static SecurityBaseline parseJson(String json, SecurityBaseline b) {
        String ll = json.toLowerCase(Locale.ROOT);
        // Check for 0.0.0.0/0 open to Telnet (23) or HTTP (80)
        if (ll.contains("0.0.0.0/0") || ll.contains("\"cidrip\": \"0.0.0.0/0\"")) {
            // Check which ports are open
            Matcher mPort = Pattern.compile("\"fromport\"\\s*:\\s*(\\d+).*?\"toport\"\\s*:\\s*(\\d+)", Pattern.CASE_INSENSITIVE | Pattern.DOTALL).matcher(json);
            while (mPort.find()) {
                int from = Integer.parseInt(mPort.group(1));
                int to = Integer.parseInt(mPort.group(2));
                if (from <= 23 && to >= 23) {
                    b.networkSegmentation.publicSensitiveIngress = true;
                    b.networkSegmentation.evidence.add("JSON: 0.0.0.0/0 permits sensitive port 23");
                    b.managementPlane.telnetEnabled = true;
                    b.managementPlane.telnetEvidence.add("JSON: 0.0.0.0/0 permits port 23 (Telnet)");
                }
                if (from <= 80 && to >= 80) {
                    b.networkSegmentation.publicSensitiveIngress = true;
                    b.networkSegmentation.evidence.add("JSON: 0.0.0.0/0 permits sensitive port 80");
                    b.managementPlane.httpEnabled = true;
                    b.managementPlane.httpEvidence.add("JSON: 0.0.0.0/0 permits port 80 (HTTP)");
                }
                if (from <= 22 && to >= 22) {
                    b.networkSegmentation.publicSensitiveIngress = true;
                    b.networkSegmentation.evidence.add("JSON: 0.0.0.0/0 permits sensitive port 22");
                    b.managementPlane.sshEnabled = true;
                    // Check for weak ciphers? AWS SG doesn't expose ciphers
                    b.managementPlane.sshEvidence.add("JSON: port 22 open");
                }
            }
            // If no explicit telnet/http but 0.0.0.0/0 with all ports
            if (ll.contains("\"ipprotocol\": \"-1\"") && ll.contains("0.0.0.0/0")) {
                b.managementPlane.telnetEnabled = true;
                b.managementPlane.httpEnabled = true;
                b.acl.hasGranularAcls = false;
                b.acl.evidence.add("JSON: Security Group allows all traffic from 0.0.0.0/0");
                b.networkSegmentation.publicSensitiveIngress = true;
                b.networkSegmentation.evidence.add("JSON: Security Group allows all traffic from 0.0.0.0/0");
            }
        }
        // Check for granular ACLs: presence of specific CIDR not 0.0.0.0/0
        if (ll.contains("\"cidrip\"") && !ll.contains("0.0.0.0/0")) {
            b.acl.hasGranularAcls = true;
            b.acl.evidence.add("JSON: Security Group restricts CIDR");
            SecurityBaseline.Acl.AclEntry e = new SecurityBaseline.Acl.AclEntry();
            e.name = "aws_sg"; e.type = "sg"; e.action = "permit"; e.evidence = "JSON: SG rule";
            b.acl.entries.add(e);
            if (b.networkSegmentation.publicSensitiveIngress == null)
                b.networkSegmentation.publicSensitiveIngress = false;
        }
        // Check for logging: CloudTrail / VPC Flow Logs
        if (ll.contains("cloudtrail") || ll.contains("flowlogs") || ll.contains("\"loggroupname\"")) {
            b.logging.enabled = true;
            b.logging.evidence.add("JSON: CloudTrail/Flow Logs enabled");
        } else if (ll.contains("\"securitygroups\"") && !ll.contains("log")) {
            // No logging found in SG export — flag as potential
            b.logging.enabled = false;
        }
        // Check for weak auth: hardcoded secrets in userData?
        if (ll.contains("password") || ll.contains("secret")) {
            SecurityBaseline.Authentication.User u = new SecurityBaseline.Authentication.User();
            u.name = "aws_user"; u.authType = ll.contains("secret") ? "secret" : "password"; u.evidence.add("JSON: password/secret in config");
            b.authentication.users.add(u);
        }
        // Crypto: ELB listener with weak ciphers
        if (ll.contains("elb") || ll.contains("listener")) {
            if (ll.contains("des") || ll.contains("rc4") || ll.contains("tls1.0") || ll.contains("tls1.1")) {
                b.cryptography.weakCiphersFound.add("JSON: weak TLS/cipher in ELB");
                b.cryptography.strongCryptoEnabled = false;
            }
            if (ll.contains("tls1.2") || ll.contains("tls1.3") || ll.contains("aes128") || ll.contains("aes256")) {
                b.cryptography.strongCryptoEnabled = true;
                b.cryptography.tls12OrHigher = true;
            }
        }
        return b;
    }

    private static SecurityBaseline parseCli(String configContent, SecurityBaseline b) {
        String[] rawLines = configContent.split("\\r?\\n", -1);
        for (int i = 0; i < rawLines.length; i++) {
            String line = rawLines[i].trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            int num = i + 1;
            String ll = line.toLowerCase(Locale.ROOT);
            String evidence = "L" + num + ": " + line;

            // AWS CLI: aws ec2 authorize-security-group-ingress --group-id sg-123 --protocol tcp --port 23 --cidr 0.0.0.0/0
            if (ll.contains("0.0.0.0/0")) {
                if (ll.matches(".*(--port\\s+)?(22|23|80|443|3389|5432)\\b.*") || ll.contains("--protocol -1")) {
                    b.networkSegmentation.publicSensitiveIngress = true;
                    b.networkSegmentation.evidence.add(evidence);
                }
                if (ll.contains("port 23") || ll.contains("--port 23") || ll.contains("telnet")) {
                    b.managementPlane.telnetEnabled = true; b.managementPlane.telnetEvidence.add(evidence);
                }
                if (ll.contains("port 80") || ll.contains("--port 80") || ll.contains("http")) {
                    b.managementPlane.httpEnabled = true; b.managementPlane.httpEvidence.add(evidence);
                }
                if (ll.contains("port 22") || ll.contains("--port 22")) {
                    b.managementPlane.sshEnabled = true; b.managementPlane.sshEvidence.add(evidence);
                }
            }
            // ACL via NACL
            if (ll.contains("nacl") || ll.contains("network-acl") || ll.contains("cidr")) {
                SecurityBaseline.Acl.AclEntry e = new SecurityBaseline.Acl.AclEntry();
                e.name = "aws_nacl"; e.type = "nacl"; e.action = ll.contains("deny") ? "deny" : "permit"; e.evidence = evidence;
                b.acl.entries.add(e); b.acl.hasGranularAcls = true; b.acl.evidence.add(evidence);
            }
            // Logging via CloudTrail
            if (ll.contains("cloudtrail") || ll.contains("flow") && ll.contains("log")) {
                b.logging.enabled = true; b.logging.evidence.add(evidence);
                Matcher m = Pattern.compile("log[^\\s]*\\s+(\\S+)", Pattern.CASE_INSENSITIVE).matcher(line);
                if (m.find()) b.logging.hosts.add(m.group(1));
            }
        }
        return b;
    }
}
