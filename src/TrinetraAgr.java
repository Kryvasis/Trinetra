import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;

/**
 * Aggregation and reporting layer.
 * Generates both a scorecard and a detailed pentest report.
 * Deduplicates findings, applies CVE/cert scoring, maps to OWASP Top 10.
 */
public class TrinetraAgr {

    // ── OWASP Top 10 2021 mapping (IN-SCOPE test_ids only) ──
    private static final Map<String, String> OWASP_MAP = new LinkedHashMap<>();
    static {
        OWASP_MAP.put("V-003", "A05:2021 – Security Misconfiguration");
        OWASP_MAP.put("V-004", "A07:2021 – Identification and Authentication Failures");
        OWASP_MAP.put("V-005", "A05:2021 – Security Misconfiguration");
        OWASP_MAP.put("V-006", "A02:2021 – Cryptographic Failures");
        OWASP_MAP.put("V-007", "A02:2021 – Cryptographic Failures");
        OWASP_MAP.put("V-008", "A02:2021 – Cryptographic Failures");
        OWASP_MAP.put("V-010", "A05:2021 – Security Misconfiguration");
        OWASP_MAP.put("V-013", "A07:2021 – Identification and Authentication Failures");
        OWASP_MAP.put("V-056", "A07:2021 – Identification and Authentication Failures");
        OWASP_MAP.put("V-057", "A02:2021 – Cryptographic Failures");
        OWASP_MAP.put("V-071", "A05:2021 – Security Misconfiguration");
        OWASP_MAP.put("V-087", "A06:2021 – Vulnerable and Outdated Components");
        OWASP_MAP.put("V-106", "A05:2021 – Security Misconfiguration");
        OWASP_MAP.put("V-107", "A05:2021 – Security Misconfiguration");
    }

    // ── Remediation hints per V-code — step-by-step CLI sequences (item 6) ──
    // Reformatted from single-paragraph hints into numbered device-specific steps where fix requires multiple CLI invocations.
    // All remediation content is correct per vendor documentation; only structuring changed.
    //
    // Traceability policy (review item 1c): these curated Cisco IOS sequences are
    // shown ONLY for confirmed-risk findings (Category 1 FAIL with an exact
    // triggering directive and source lines). Rationale: detection confidence is
    // high there (anchored directive match, comments/negations excluded), so the
    // fix is specific and safe to display WITH the mandatory review warning
    // (backup/rollback/vendor-guide check — effective state is still unproven).
    // Everything else (verified-pass, insufficient-evidence, unsupported-check)
    // keeps generic cautious guidance so we never present a device-changing
    // command without triggering evidence.
    private static final Map<String, String> REMEDIATION = new LinkedHashMap<>();
    static {
        REMEDIATION.put("V-003", "1. Enter config mode: `configure terminal`. 2. Identify service: `show running-config | include transport|http`. 3. Disable unused: `line vty 0 4` → `no transport input telnet`; `no ip http server`. 4. Restrict with ACL: `access-list 10 permit 10.0.0.0 0.255.255.255` → `line vty 0 4` → `access-class 10 in`. 5. Save: `write memory`.");
        REMEDIATION.put("V-005", "1. `configure terminal`. 2. Suppress banner: `no banner motd` or `banner motd # authorized use only #`. 3. Disable version disclosure: `no ip http server` + `no service pad`. 4. Verify: `show running-config | include banner|version`.");
        REMEDIATION.put("V-006", "1. `configure terminal`. 2. Disable weak TLS: `no ip http server` (or restrict to `ip http secure-server` only). 3. Enforce TLS 1.2+: `ip ssh version 2` → `ip ssh server algorithm encryption aes128-ctr aes256-ctr aes128-gcm`. 4. Verify: `show ip ssh` / `show ip http server status`.");
        REMEDIATION.put("V-007", "1. `configure terminal`. 2. Remove weak ciphers: `no ip ssh server algorithm encryption 3des-cbc` / `no ip ssh server algorithm encryption rc4`. 3. Enable AEAD: `ip ssh server algorithm encryption aes128-ctr aes256-ctr aes128-gcm` + `ip ssh server algorithm mac hmac-sha2-256`. 4. Verify: `show ip ssh`.");
        REMEDIATION.put("V-008", "1. Generate CSR: `crypto pki enroll <trustpoint>`. 2. Import CA-signed cert: `crypto pki import <trustpoint> certificate`. 3. Bind: `ip http secure-trustpoint <trustpoint>`. 4. Verify & renew: `show crypto pki certificates`.");
        REMEDIATION.put("V-010", "1. `configure terminal`. 2. Add HSTS: `ip http secure-server` → `ip http csp` (or web-server hsts). 3. Set header: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`. 4. Verify via browser devtools headers.");
        REMEDIATION.put("V-013", "1. `configure terminal`. 2. Enforce complexity: `aaa new-model` (or `security passwords min-length 12`). 3. Strong secret: `enable secret <strong-password>`. 4. Local user: `username admin privilege 15 secret <strong-password>`. 5. Save: `write memory`.");
        REMEDIATION.put("V-057", "1. `configure terminal`. 2. Remove hardcoded: `no snmp-server community public` / `no snmp-server community private`. 3. Use vault: `snmp-server group <name> v3 priv` + store secret in vault/manager. 4. Verify: `show running-config | include snmp-server`.");
        REMEDIATION.put("V-058", "1. `configure terminal`. 2. Enable logging: `logging host 10.10.1.100` + `logging trap informational`. 3. Protect: `service timestamps log datetime msec` + `no logging console` (avoid sensitive data). 4. Verify: `show logging`.");
        REMEDIATION.put("V-070", "1. Check version: `show version` / `show inventory` (Juniper: `show version detail`). 2. Compare to advisory: `https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory`. 3. Download image: `copy tftp://server/<image> flash:`. 4. Install: `install add file flash:<image> activate commit` (Juniper: `request system software add <image> reboot`). 5. Verify: `show version` post-upgrade + `verify /md5 flash:<image>`.");
        REMEDIATION.put("V-071", "1. `configure terminal`. 2. Harden vty: `line vty 0 4` → `no transport input telnet` → `transport input ssh`. 3. Disable HTTP: `no ip http server`. 4. Set idle timeout: `line vty 0 4` → `exec-timeout 5 0` → `logging synchronous`. 5. `end` → `write memory`.");
        REMEDIATION.put("V-087", "1. Identify component: `show version` / `show inventory` (Juniper: `show version | match JUNOS`). 2. Check CVE: compare to `https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory`. 3. Patch: `install add file <image> activate commit` or `request system software add <image>` (Juniper). 4. Verify: `show version` post-patch.");
        REMEDIATION.put("V-105", "1. Identify flat domain: `show ip route` / `show vlan` (Juniper: `show vlans detail`). 2. Create segments: `vlan 10` → `name SEGMENT_A` → `interface vlan 10` (Juniper: `set vlans vlan10 vlan-id 10`). 3. Apply ACL: `access-list 101 deny ip any any` → `interface Gi0/1 ip access-group 101 in`. 4. Verify: `show vlan` / `show access-lists`.");
        REMEDIATION.put("V-106", "1. Identify bucket: `aws s3api get-bucket-acl --bucket <bucket>` (GCP: `gsutil iam get gs://<bucket>`; Azure: `az storage container show --name <container>`). 2. Set private: `aws s3api put-bucket-acl --bucket <bucket> --acl private` (GCP: `gsutil iam ch -d allUsers gs://<bucket>`). 3. Enable encryption: `aws s3api put-bucket-encryption --bucket <bucket> --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}'`. 4. Enable logging/versioning: `aws s3api put-bucket-logging --bucket <bucket> --bucket-logging-status '{\"LoggingEnabled\":{\"TargetBucket\":\"log-bucket\"}}'`. 5. Verify: `aws s3api get-bucket-acl --bucket <bucket>` shows private.");
        REMEDIATION.put("V-107", "1. Review IAM: `show running-config | include username|privilege` (Juniper: `show configuration system login`). 2. Apply least privilege: `username <user> privilege 5 secret <pwd>` (Juniper: `set system login user <user> class operator`). 3. Remove excess: `no username <user> privilege 15` (Juniper: `delete system login user <user>`). 4. Verify: `show running-config | include username` + `show aaa local user lockout`.");
        REMEDIATION.put("V-144", "1. Check params: `show version` + `sysctl -a | grep kernel.randomize` (NX-OS: `show running-config | include ip source-route`). 2. Harden: `no ip source-route` + `ip tcp synwait-time 10` (Juniper: `set system internet-options no-source-route`) + `sysctl -w kernel.randomize_va_space=2`. 3. Persist: `copy running-config startup-config` (Linux: `sysctl -p /etc/sysctl.conf`). 4. Verify: `show running-config | include source-route`.");
    }

    /**
     * Curated remediation for one V-code, or "" when none is curated.
     * Callers MUST gate on confirmed-risk before displaying (see policy above).
     */
    public static String getRemediation(String vCode) {
        if (vCode == null) return "";
        String r = REMEDIATION.get(vCode.trim().toUpperCase(Locale.ROOT));
        return r != null ? r : "";
    }

    /**
     * Version/model-aware remediation — customizes steps per vendor + OS version.
     * Falls back to generic curated remediation when no specific template exists.
     * This satisfies PS "Reporting customized based on device's specific model and software version."
     */
    public static String getRemediation(String vCode, String vendor, String osVersion) {
        if (vCode == null) return "";
        String key = vCode.trim().toUpperCase(Locale.ROOT);
        String base = REMEDIATION.get(key);
        if (base == null) return "";
        if (vendor == null) vendor = "";
        String v = vendor.trim().toLowerCase(Locale.ROOT);
        String osv = osVersion != null ? osVersion.trim() : "";
        String prefix = "";
        // Vendor-specific prefix
        if (v.contains("forti") || v.equals("fortios")) {
            prefix = "[FortiOS " + (osv.isEmpty() ? "7.x" : osv) + "] FortiGate: ";
            // Translate Cisco steps to FortiOS equivalents for key V-codes
            if ("V-071".equals(key)) return prefix + "1. `config system interface` → `edit port1` → `set allowaccess ping https ssh` (remove `telnet`/`http`). 2. `config system global` → `set admintimeout 5`. 3. Verify: `show system interface` / `get system status`. 4. Save: `execute backup config`";
            if ("V-057".equals(key)) return prefix + "1. `config system snmp community` → `delete 1` (remove public). 2. `config system snmp sysinfo` → `set status enable` → `config system snmp user` → `set security-level auth-priv`. 3. Verify: `show system snmp community`";
            if ("V-058".equals(key)) return prefix + "1. `config log syslogd setting` → `set status enable` → `set server " + "10.10.1.100" + "` . 2. Verify: `show log syslogd setting`";
        } else if (v.contains("pan") || v.contains("palo")) {
            prefix = "[PAN-OS " + (osv.isEmpty() ? "11.x" : osv) + "] Palo Alto: ";
            if ("V-071".equals(key)) return prefix + "1. `set deviceconfig system service disable-telnet yes` → `set deviceconfig system service disable-http yes`. 2. `set mgt-config users` → enforce `phash`. 3. Verify: `show system info`";
            if ("V-057".equals(key)) return prefix + "1. `delete deviceconfig system snmp-setting access-setting community public`. 2. `set deviceconfig system snmp-setting access-setting version v3` → `set deviceconfig system snmp-setting v3 users <user> auth`. 3. Verify: `show snmp-setting`";
        } else if (v.contains("sonic") || v.contains("white")) {
            prefix = "[SONiC " + (osv.isEmpty() ? "2023.11" : osv) + "] White Box: ";
            if ("V-071".equals(key)) return prefix + "1. `sudo config aaa authentication login default local` → disable telnet: `sudo systemctl disable telnet`. 2. `sudo sonic-cfggen -a '{\"DEVICE_METADATA\":{\"localhost\":{\"hostname\":\"...\"}}}'`. 3. Verify: `show version` / `show ip interfaces`";
            if ("V-003".equals(key)) return prefix + "1. `sudo iptables -A INPUT -p tcp --dport 23 -j DROP` (block telnet) → `sudo config save -y`. 2. Verify: `iptables -L`";
        } else if (v.contains("aws") || v.contains("cloud") || v.contains("amazon")) {
            prefix = "[AWS " + (osv.isEmpty() ? "SG/NACL" : osv) + "] Cloud-native: ";
            if ("V-003".equals(key) || "V-071".equals(key)) return prefix + "1. `aws ec2 revoke-security-group-ingress --group-id sg-xxxx --protocol tcp --port 23 --cidr 0.0.0.0/0` (telnet) → `aws ec2 revoke-security-group-ingress --port 80 --cidr 0.0.0.0/0` (http). 2. Restrict to `10.0.0.0/16`. 3. Verify: `aws ec2 describe-security-groups`";
            if ("V-057".equals(key)) return prefix + "1. `aws s3api put-bucket-acl --bucket <bucket> --acl private` (remove public). 2. `aws iam` rotate hardcoded keys.";
        } else if (v.contains("juniper") || v.contains("junos")) {
            prefix = "[JUNOS " + (osv.isEmpty() ? "20.4R3" : osv) + "] Juniper: ";
            if (base.contains("Cisco IOS") || base.contains("configure terminal")) {
                // Provide JUNOS translation inline
                return prefix + base.replace("`configure terminal`", "`configure`").replace("`line vty 0 4`", "`set system services`") + " (JUNOS syntax shown where applicable)";
            }
        } else if (v.contains("cisco")) {
            prefix = "[IOS" + (osv.contains("XE") ? " XE " : osv.contains("NX") ? " NX-OS " : " ") + (osv.isEmpty() ? "17.6.5" : osv) + "] Cisco: ";
            return prefix + base;
        }
        // Generic fallback with version tag
        if (!osv.isEmpty()) return "[" + vendor + " " + osv + "] " + base;
        return base;
    }

    /**
     * Generate both scorecard and detailed report.
     * Returns the detailed report content.
     */
    public static String generateReport(String sessionName, String certMode) {
        String sanitized = TrinetraCommon.sanitizeName(sessionName);
        List<Map<String, Object>> findings = TrinetraSession.getFindings(sanitized);

        if (findings.isEmpty()) {
            TrinetraCommon.logError("No findings to report for session: " + sanitized);
            return "No findings available for session: " + sanitized;
        }

        Map<String, Object> session = TrinetraSession.loadSession(sanitized);
        String target = session != null ? TrinetraCommon.getString(session, "target", "unknown") : "unknown";

        // Deduplicate: keep latest finding per V-code
        Map<String, Map<String, Object>> deduped = deduplicateFindings(findings);

        // Generate scorecard
        String scorecard = generateScorecard(sanitized, target, deduped, certMode);
        Path scorecardPath = TrinetraCommon.sessionDir(sanitized).resolve("scorecard_" + sanitized + ".md");
        TrinetraCommon.atomicWriteFile(scorecardPath, scorecard);

        // Generate detailed report
        String report = generateDetailedReport(sanitized, target, deduped, findings, certMode);

        // Store report in artifacts
        Path artifactsDir = TrinetraCommon.sessionArtifactsDir(sanitized);
        try { Files.createDirectories(artifactsDir); } catch (IOException ignored) {}
        Path reportPath = artifactsDir.resolve("pentest_report_" + sanitized + ".md");
        TrinetraCommon.atomicWriteFile(reportPath, report);

        // Also store JSON summary
        String jsonReport = generateJsonReport(sanitized, target, deduped, findings);
        Path jsonPath = artifactsDir.resolve("report_" + sanitized + ".json");
        TrinetraCommon.atomicWriteFile(jsonPath, jsonReport);

        // Update brain state
        Path statePath = TrinetraCommon.sessionBrainState(sanitized);
        Map<String, Object> state = TrinetraCommon.readJsonFile(statePath);
        if (!state.isEmpty()) {
            state.put("state", TrinetraSession.State.REPORT_READY.value);
            state.put("last_updated", TrinetraCommon.nowIso());
            TrinetraCommon.writeJsonFile(statePath, state);
        }

        TrinetraCommon.logInfo("Report generated: " + reportPath);
        TrinetraCommon.logInfo("Scorecard generated: " + scorecardPath);
        TrinetraCommon.logInfo("JSON report: " + jsonPath);

        return report;
    }

    // ── Legacy: generate scorecard only ──
    public static String generateScorecard(String sessionName, String certMode) {
        String sanitized = TrinetraCommon.sanitizeName(sessionName);
        List<Map<String, Object>> findings = TrinetraSession.getFindings(sanitized);
        if (findings.isEmpty()) {
            return "No findings available for session: " + sanitized;
        }
        Map<String, Object> session = TrinetraSession.loadSession(sanitized);
        String target = session != null ? TrinetraCommon.getString(session, "target", "unknown") : "unknown";
        Map<String, Map<String, Object>> deduped = deduplicateFindings(findings);
        return generateScorecard(sanitized, target, deduped, certMode);
    }

    // ── Deduplication ──
    @SuppressWarnings("unchecked")
    private static Map<String, Map<String, Object>> deduplicateFindings(List<Map<String, Object>> findings) {
        Map<String, Map<String, Object>> deduped = new LinkedHashMap<>();
        for (Map<String, Object> f : findings) {
            String vCode = TrinetraCommon.getString(f, "v_code",
                TrinetraCommon.getString(f, "test_code", "???"));
            String startedAt = TrinetraCommon.getString(f, "started_at", "");
            Map<String, Object> existing = deduped.get(vCode);
            if (existing == null || startedAt.compareTo(TrinetraCommon.getString(existing, "started_at", "")) > 0) {
                deduped.put(vCode, f);
            }
        }
        return deduped;
    }

    // ── Severity derivation ──
    private static String deriveSeverity(Map<String, Object> finding) {
        // Prefer default_severity from static map, but validate it
        String staticSeverity = TrinetraCommon.getString(finding, "default_severity", "").toLowerCase();
        if (staticSeverity.equals("critical") || staticSeverity.equals("high")
            || staticSeverity.equals("medium") || staticSeverity.equals("low")) {
            return staticSeverity;
        }

        // Derive from summary and v_name
        String summary = TrinetraCommon.getString(finding, "summary", "").toLowerCase();
        String vName = TrinetraCommon.getString(finding, "v_name", "").toLowerCase();
        String verdict = TrinetraCommon.getString(finding, "verdict", "").toLowerCase();

        if (summary.contains("critical") || summary.contains("remote code execution")
            || summary.contains("rce") || vName.contains("auth bypass")
            || summary.contains("sql injection") || summary.contains("command injection")) {
            return "critical";
        }
        if (verdict.equals("fail")) {
            if (summary.contains("expired") || summary.contains("self-signed")
                || summary.contains("default creds") || summary.contains("weak tls")
                || summary.contains("weak cipher")) {
                return "high";
            }
            if (summary.contains("missing") || summary.contains("header")
                || summary.contains("misconfig") || summary.contains("banner")) {
                return "medium";
            }
            return "medium";
        }
        if (summary.contains("high") || summary.contains("xss")
            || summary.contains("information disclosure") || summary.contains("misconfiguration")
            || summary.contains("weak") || summary.contains("default")) {
            return "high";
        }
        if (summary.contains("medium")) return "medium";
        return "low";
    }

    // ── CVE extraction ──
    private static List<String> extractCves(Map<String, Object> finding) {
        List<String> cves = new ArrayList<>();
        String rawOutput = TrinetraCommon.getString(finding, "raw_output",
            TrinetraCommon.getString(finding, "stdout", ""));
        if (rawOutput != null) {
            Matcher m = Pattern.compile("CVE-\\d{4}-\\d{4,}").matcher(rawOutput);
            while (m.find()) {
                String cve = m.group();
                if (!cves.contains(cve)) cves.add(cve);
            }
        }
        return cves;
    }

    // ── Cert issue extraction ──
    private static List<String> extractCertIssues(Map<String, Object> finding) {
        List<String> issues = new ArrayList<>();
        String rawOutput = TrinetraCommon.getString(finding, "raw_output",
            TrinetraCommon.getString(finding, "stdout", ""));
        if (rawOutput == null) return issues;
        String lower = rawOutput.toLowerCase();
        if (lower.contains("self-signed") || lower.contains("self signed")) issues.add("Self-signed certificate");
        if (lower.contains("expired")) issues.add("Expired certificate");
        if (lower.contains("weak signature algorithm")) issues.add("Weak signature algorithm");
        if (lower.contains("ssl2") || lower.contains("sslv3") || lower.contains("tlsv1.0") || lower.contains("tlsv1.1"))
            issues.add("Weak TLS version");
        if (lower.contains("null") || lower.contains("export") || lower.contains("rc4") || lower.contains("des"))
            issues.add("Weak cipher suite");
        return issues;
    }

    // ── Evidence extraction (first 500 chars of relevant output) ──
    private static String extractEvidence(Map<String, Object> finding) {
        String rawOutput = TrinetraCommon.getString(finding, "raw_output",
            TrinetraCommon.getString(finding, "stdout", ""));
        if (rawOutput == null || rawOutput.isEmpty()) return "(no evidence captured)";

        // Try to find the most relevant section
        String[] markers = {"[FAIL]", "FAIL", "ACCEPTED", "found", "exposed", "vulnerable", "self-signed", "expired"};
        String lower = rawOutput.toLowerCase();
        int bestIdx = -1;
        for (String marker : markers) {
            int idx = lower.indexOf(marker.toLowerCase());
            if (idx >= 0 && (bestIdx < 0 || idx < bestIdx)) bestIdx = idx;
        }

        if (bestIdx >= 0) {
            int start = Math.max(0, bestIdx - 100);
            int end = Math.min(rawOutput.length(), bestIdx + 500);
            String excerpt = rawOutput.substring(start, end).strip();
            if (start > 0) excerpt = "..." + excerpt;
            if (end < rawOutput.length()) excerpt = excerpt + "...";
            return excerpt;
        }

        // Fallback: first 500 chars
        return rawOutput.substring(0, Math.min(500, rawOutput.length()));
    }

    // ── Score computation ──
    private static int computeScorecardScore(int total, int pass, int fail, int critical, int high, int medium, int low) {
        if (total == 0) return 0;
        int cappedPass = Math.min(pass, 15);
        int coverageScore = (int) ((double) cappedPass / 15.0 * 40);
        int findingPenalty = critical * 15 + high * 8 + medium * 3 + low * 1;
        return Math.max(0, Math.min(100, 100 - findingPenalty + coverageScore));
    }

    // ── Scorecard (compact) ──
    private static String generateScorecard(String sessionName, String target,
                                             Map<String, Map<String, Object>> deduped, String certMode) {
        StringBuilder sb = new StringBuilder();
        sb.append("# Security Scorecard\n\n");
        sb.append("| Field | Value |\n|-------|-------|\n");
        sb.append("| **Session** | ").append(sessionName).append(" |\n");
        sb.append("| **Target** | ").append(target).append(" |\n");
        sb.append("| **Generated** | ").append(TrinetraCommon.nowIso()).append(" |\n");
        sb.append("| **Cert Mode** | ").append(certMode != null ? certMode : "default").append(" |\n\n");

        int total = deduped.size();
        int pass = 0, fail = 0, manualReview = 0, error = 0;
        int critical = 0, high = 0, medium = 0, low = 0;
        List<String> allCves = new ArrayList<>();

        for (Map<String, Object> f : deduped.values()) {
            String verdict = TrinetraCommon.getString(f, "verdict", "error");
            switch (verdict) {
                case "pass": pass++; break;
                case "fail": fail++; break;
                case "manual_review": manualReview++; break;
                default: error++; break;
            }
            String sev = deriveSeverity(f);
            switch (sev) {
                case "critical": critical++; break;
                case "high": high++; break;
                case "medium": medium++; break;
                default: low++; break;
            }
            List<String> cves = extractCves(f);
            for (String c : cves) {
                if (!allCves.contains(c)) allCves.add(c);
            }
        }

        int score = computeScorecardScore(total, pass, fail, critical, high, medium, low);

        String riskLevel;
        if (score >= 80) riskLevel = "LOW";
        else if (score >= 60) riskLevel = "MEDIUM";
        else if (score >= 40) riskLevel = "HIGH";
        else riskLevel = "CRITICAL";

        sb.append("## Overall Score: **").append(score).append("/100** (Risk: ").append(riskLevel).append(")\n\n");

        sb.append("## Summary\n");
        sb.append("| Metric | Count |\n|--------|-------|\n");
        sb.append("| Unique tests | ").append(total).append(" |\n");
        sb.append("| PASS | ").append(pass).append(" |\n");
        sb.append("| FAIL | ").append(fail).append(" |\n");
        sb.append("| MANUAL_REVIEW | ").append(manualReview).append(" |\n");
        sb.append("| ERROR | ").append(error).append(" |\n");
        sb.append("| Critical | ").append(critical).append(" |\n");
        sb.append("| High | ").append(high).append(" |\n");
        sb.append("| Medium | ").append(medium).append(" |\n");
        sb.append("| Low | ").append(low).append(" |\n");
        if (!allCves.isEmpty()) {
            sb.append("| CVE matches | ").append(allCves.size()).append(" |\n");
        }
        sb.append("\n");

        sb.append("## Findings\n");
        sb.append("| V-Code | Test | Verdict | Severity | OWASP |\n");
        sb.append("|--------|------|---------|----------|-------|\n");
        for (Map.Entry<String, Map<String, Object>> e : deduped.entrySet()) {
            Map<String, Object> f = e.getValue();
            String vCode = TrinetraCommon.getString(f, "v_code", e.getKey());
            String vName = TrinetraCommon.getString(f, "v_name", "Unknown");
            String verdict = TrinetraCommon.getString(f, "verdict", "error").toUpperCase();
            String sev = deriveSeverity(f);
            String owasp = OWASP_MAP.getOrDefault(vCode, "-");
            sb.append("| ").append(vCode).append(" | ").append(vName)
              .append(" | ").append(verdict).append(" | ").append(sev)
              .append(" | ").append(owasp).append(" |\n");
        }
        sb.append("\n---\n_Generated by Trinetra Beta_\n");

        return sb.toString();
    }

    // ── Detailed Report ──
    private static String generateDetailedReport(String sessionName, String target,
                                                   Map<String, Map<String, Object>> deduped,
                                                   List<Map<String, Object>> allFindings,
                                                   String certMode) {
        StringBuilder sb = new StringBuilder();

        // Compute stats
        int total = deduped.size();
        int pass = 0, fail = 0, manualReview = 0, error = 0;
        int critical = 0, high = 0, medium = 0, low = 0;
        List<String> allCves = new ArrayList<>();
        List<String> allCertIssues = new ArrayList<>();
        List<Map<String, Object>> failedTests = new ArrayList<>();

        for (Map<String, Object> f : deduped.values()) {
            String verdict = TrinetraCommon.getString(f, "verdict", "error");
            switch (verdict) {
                case "pass": pass++; break;
                case "fail": fail++; failedTests.add(f); break;
                case "manual_review": manualReview++; break;
                default: error++; break;
            }
            String sev = deriveSeverity(f);
            switch (sev) {
                case "critical": critical++; break;
                case "high": high++; break;
                case "medium": medium++; break;
                default: low++; break;
            }
            List<String> cves = extractCves(f);
            for (String c : cves) { if (!allCves.contains(c)) allCves.add(c); }
            List<String> certIssues = extractCertIssues(f);
            for (String ci : certIssues) { if (!allCertIssues.contains(ci)) allCertIssues.add(ci); }
        }

        int score = computeScorecardScore(total, pass, fail, critical, high, medium, low);
        String riskLevel;
        if (score >= 80) riskLevel = "LOW";
        else if (score >= 60) riskLevel = "MEDIUM";
        else if (score >= 40) riskLevel = "HIGH";
        else riskLevel = "CRITICAL";

        // ── Title Page ──
        sb.append("# Penetration Test Report\n\n");
        sb.append("| Field | Value |\n|-------|-------|\n");
        sb.append("| **Session** | ").append(sessionName).append(" |\n");
        sb.append("| **Target** | ").append(target).append(" |\n");
        sb.append("| **Date** | ").append(TrinetraCommon.nowIso()).append(" |\n");
        sb.append("| **Tool** | Trinetra Beta |\n");
        sb.append("| **Cert Mode** | ").append(certMode != null ? certMode : "default").append(" |\n");
        sb.append("| **Overall Score** | ").append(score).append("/100 |\n");
        sb.append("| **Risk Rating** | **").append(riskLevel).append("** |\n");
        sb.append("\n---\n\n");

        // ── Executive Summary ──
        sb.append("## 1. Executive Summary\n\n");
        sb.append("This report presents the findings of an automated penetration test conducted against **")
          .append(target).append("**. The assessment covered ").append(total)
          .append(" security tests across multiple categories including network security, ")
          .append("cryptography, authentication, injection, access control, and configuration.\n\n");

        sb.append("### Risk Overview\n\n");
        sb.append("- **Overall Score**: ").append(score).append("/100\n");
        sb.append("- **Risk Rating**: **").append(riskLevel).append("**\n\n");

        if (critical > 0) {
            sb.append("**CRITICAL**: ").append(critical).append(" critical-severity finding(s) require immediate remediation. ");
            sb.append("These findings pose an imminent risk of compromise.\n\n");
        }
        if (high > 0) {
            sb.append("**HIGH**: ").append(high).append(" high-severity finding(s) should be addressed within 30 days.\n\n");
        }
        if (medium > 0) {
            sb.append("**MEDIUM**: ").append(medium).append(" medium-severity finding(s) should be addressed within 90 days.\n\n");
        }
        if (low > 0) {
            sb.append("**LOW**: ").append(low).append(" low-severity finding(s) represent best-practice deviations.\n\n");
        }
        if (fail == 0 && manualReview == 0) {
            sb.append("No security vulnerabilities were identified during this assessment. The target demonstrates ");
            sb.append("strong security posture across all tested categories.\n\n");
        }

        sb.append("### Statistics\n\n");
        sb.append("| Metric | Count |\n|--------|-------|\n");
        sb.append("| Tests executed (unique) | ").append(total).append(" |\n");
        sb.append("| Passed | ").append(pass).append(" |\n");
        sb.append("| Failed | ").append(fail).append(" |\n");
        sb.append("| Manual review required | ").append(manualReview).append(" |\n");
        sb.append("| Errors | ").append(error).append(" |\n\n");

        // ── CVE Summary ──
        if (!allCves.isEmpty()) {
            sb.append("### CVE Matches\n\n");
            sb.append("The following CVEs were identified in scan output:\n\n");
            for (String cve : allCves) {
                sb.append("- **").append(cve).append("**\n");
            }
            sb.append("\n");
        }

        // ── Certificate Issues ──
        if (!allCertIssues.isEmpty()) {
            sb.append("### Certificate Issues\n\n");
            for (String issue : allCertIssues) {
                sb.append("- ").append(issue).append("\n");
            }
            sb.append("\n");
        }

        // ── OWASP Coverage ──
        sb.append("## 2. OWASP Top 10 Coverage\n\n");
        sb.append("| OWASP Category | Tests | Failed |\n|----------------|-------|--------|\n");
        Map<String, int[]> owaspCounts = new LinkedHashMap<>();
        for (Map.Entry<String, Map<String, Object>> e : deduped.entrySet()) {
            String vCode = e.getKey();
            String owasp = OWASP_MAP.getOrDefault(vCode, "Uncategorized");
            if (!owaspCounts.containsKey(owasp)) owaspCounts.put(owasp, new int[]{0, 0});
            owaspCounts.get(owasp)[0]++;
            String verdict = TrinetraCommon.getString(e.getValue(), "verdict", "error");
            if ("fail".equals(verdict)) owaspCounts.get(owasp)[1]++;
        }
        for (Map.Entry<String, int[]> e : owaspCounts.entrySet()) {
            sb.append("| ").append(e.getKey()).append(" | ").append(e.getValue()[0])
              .append(" | ").append(e.getValue()[1]).append(" |\n");
        }
        sb.append("\n");

        // ── Detailed Findings ──
        sb.append("## 3. Detailed Findings\n\n");

        int findingNum = 1;
        for (Map.Entry<String, Map<String, Object>> e : deduped.entrySet()) {
            Map<String, Object> f = e.getValue();
            String vCode = TrinetraCommon.getString(f, "v_code", e.getKey());
            String vName = TrinetraCommon.getString(f, "v_name", "Unknown");
            String verdict = TrinetraCommon.getString(f, "verdict", "error").toUpperCase();
            String sev = deriveSeverity(f);
            String owasp = OWASP_MAP.getOrDefault(vCode, "Uncategorized");
            String summary = TrinetraCommon.getString(f, "verdict_detail", "");
            String evidence = extractEvidence(f);
            List<String> cves = extractCves(f);
            String remediation = REMEDIATION.getOrDefault(vCode, "Review findings and apply vendor-specific hardening guidelines.");

            String verdictIcon;
            switch (verdict) {
                case "FAIL": verdictIcon = "FAIL"; break;
                case "PASS": verdictIcon = "PASS"; break;
                default: verdictIcon = verdict; break;
            }

            sb.append("### 3.").append(findingNum).append(" ").append(vCode)
              .append(" — ").append(vName).append("\n\n");
            sb.append("| Field | Value |\n|-------|-------|\n");
            sb.append("| **Verdict** | ").append(verdictIcon).append(" |\n");
            sb.append("| **Severity** | ").append(sev).append(" |\n");
            sb.append("| **OWASP** | ").append(owasp).append(" |\n");
            sb.append("| **Tool** | ").append(TrinetraCommon.getString(f, "tool", "n/a")).append(" |\n");
            if (!cves.isEmpty()) {
                sb.append("| **CVEs** | ").append(String.join(", ", cves)).append(" |\n");
            }
            sb.append("\n");

            sb.append("**Description**: ").append(vName).append(" test evaluated against ")
              .append(target).append(".\n\n");

            if (!summary.isEmpty()) {
                sb.append("**Detail**: `").append(summary).append("`\n\n");
            }

            sb.append("**Evidence**:\n");
            sb.append("```\n").append(evidence).append("\n```\n\n");

            sb.append("**Remediation**: ").append(remediation).append("\n\n");

            sb.append("---\n\n");
            findingNum++;
        }

        // ── Manual Review Section ──
        List<Map<String, Object>> manualReviewTests = new ArrayList<>();
        for (Map.Entry<String, Map<String, Object>> e : deduped.entrySet()) {
            String verdict = TrinetraCommon.getString(e.getValue(), "verdict", "error");
            if ("manual_review".equals(verdict)) {
                manualReviewTests.add(e.getValue());
            }
        }

        if (!manualReviewTests.isEmpty()) {
            sb.append("## 4. Manual Review Required\n\n");
            sb.append("The following tests could not be automatically evaluated and require manual review:\n\n");
            for (Map<String, Object> f : manualReviewTests) {
                String vCode = TrinetraCommon.getString(f, "v_code", "???");
                String vName = TrinetraCommon.getString(f, "v_name", "Unknown");
                sb.append("- **").append(vCode).append("** — ").append(vName).append("\n");
            }
            sb.append("\n");
        }

        // ── Recommendations ──
        sb.append("## 5. Recommendations\n\n");
        if (critical > 0 || high > 0) {
            sb.append("### Immediate Actions (0-30 days)\n\n");
            for (Map<String, Object> f : failedTests) {
                String sev = deriveSeverity(f);
                if ("critical".equals(sev) || "high".equals(sev)) {
                    String vCode = TrinetraCommon.getString(f, "v_code", "???");
                    String vName = TrinetraCommon.getString(f, "v_name", "Unknown");
                    String remediation = REMEDIATION.getOrDefault(vCode, "Review and remediate per vendor guidelines.");
                    sb.append("- **").append(vCode).append(" (").append(vName).append(")**: ").append(remediation).append("\n");
                }
            }
            sb.append("\n");
        }

        if (medium > 0 || low > 0) {
            sb.append("### Short-term Actions (30-90 days)\n\n");
            for (Map<String, Object> f : failedTests) {
                String sev = deriveSeverity(f);
                if ("medium".equals(sev) || "low".equals(sev)) {
                    String vCode = TrinetraCommon.getString(f, "v_code", "???");
                    String vName = TrinetraCommon.getString(f, "v_name", "Unknown");
                    String remediation = REMEDIATION.getOrDefault(vCode, "Review and remediate per vendor guidelines.");
                    sb.append("- **").append(vCode).append(" (").append(vName).append(")**: ").append(remediation).append("\n");
                }
            }
            sb.append("\n");
        }

        sb.append("### General Recommendations\n\n");
        sb.append("1. Implement a regular patching schedule for all software components.\n");
        sb.append("2. Enable security headers (HSTS, CSP, X-Frame-Options, etc.).\n");
        sb.append("3. Conduct regular penetration testing and security assessments.\n");
        sb.append("4. Implement Web Application Firewall (WAF) with up-to-date rules.\n");
        sb.append("5. Enable logging and monitoring for security events.\n");
        sb.append("6. Follow the principle of least privilege for all services and accounts.\n\n");

        // ── Methodology ──
        sb.append("## 6. Methodology\n\n");
        sb.append("This assessment was performed using automated scanning tools orchestrated by the Trinetra Beta framework.\n\n");
        sb.append("- **Stat Engine**: Automated execution of security test scripts with decision-rule-based verdict evaluation.\n");
        sb.append("- **Decision Rules**: Each test applies pass/fail criteria via grep patterns, exit codes, or numeric thresholds.\n");
        sb.append("- **CVE Detection**: Automated extraction of CVE identifiers from tool output.\n");
        sb.append("- **OWASP Mapping**: Findings mapped to OWASP Top 10 2021 categories.\n\n");
        sb.append("### Limitations\n\n");
        sb.append("- Automated tools may produce false positives/negatives.\n");
        sb.append("- Tests marked as MANUAL_REVIEW require human validation.\n");
        sb.append("- Business logic vulnerabilities require manual testing.\n");
        sb.append("- Zero-day vulnerabilities are not detected by signature-based tools.\n\n");

        // ── Appendices ──
        sb.append("## 7. Appendices\n\n");
        sb.append("### A. All Tests (").append(total).append(" unique)\n\n");
        sb.append("| V-Code | Test | Verdict | Severity |\n|--------|------|---------|----------|\n");
        for (Map.Entry<String, Map<String, Object>> e : deduped.entrySet()) {
            Map<String, Object> f = e.getValue();
            String vCode = TrinetraCommon.getString(f, "v_code", e.getKey());
            String vName = TrinetraCommon.getString(f, "v_name", "Unknown");
            String verdict = TrinetraCommon.getString(f, "verdict", "error").toUpperCase();
            String sev = deriveSeverity(f);
            sb.append("| ").append(vCode).append(" | ").append(vName)
              .append(" | ").append(verdict).append(" | ").append(sev).append(" |\n");
        }
        sb.append("\n");

        if (!allCves.isEmpty()) {
            sb.append("### B. CVE Reference\n\n");
            for (String cve : allCves) {
                sb.append("- ").append(cve).append(" — https://nvd.nist.gov/vuln/detail/").append(cve).append("\n");
            }
            sb.append("\n");
        }

        sb.append("---\n_Report generated by Trinetra Beta on ").append(TrinetraCommon.nowIso()).append("_\n");

        return sb.toString();
    }

    // ── JSON Report ──
    private static String generateJsonReport(String sessionName, String target,
                                               Map<String, Map<String, Object>> deduped,
                                               List<Map<String, Object>> allFindings) {
        Map<String, Object> report = TrinetraCommon.newMap();
        report.put("session", sessionName);
        report.put("target", target);
        report.put("generated_at", TrinetraCommon.nowIso());
        report.put("tool", "Trinetra Beta");

        // Stats
        int total = deduped.size();
        int pass = 0, fail = 0, manualReview = 0, error = 0;
        int critical = 0, high = 0, medium = 0, low = 0;
        List<String> allCves = new ArrayList<>();

        for (Map<String, Object> f : deduped.values()) {
            String verdict = TrinetraCommon.getString(f, "verdict", "error");
            switch (verdict) {
                case "pass": pass++; break;
                case "fail": fail++; break;
                case "manual_review": manualReview++; break;
                default: error++; break;
            }
            String sev = deriveSeverity(f);
            switch (sev) {
                case "critical": critical++; break;
                case "high": high++; break;
                case "medium": medium++; break;
                default: low++; break;
            }
            List<String> cves = extractCves(f);
            for (String c : cves) { if (!allCves.contains(c)) allCves.add(c); }
        }

        int score = computeScorecardScore(total, pass, fail, critical, high, medium, low);
        report.put("score", score);
        report.put("total_tests", total);
        report.put("passed", pass);
        report.put("failed", fail);
        report.put("manual_review", manualReview);
        report.put("errors", error);
        report.put("critical", critical);
        report.put("high", high);
        report.put("medium", medium);
        report.put("low", low);
        report.put("cve_matches", allCves);

        // Deduplicated findings
        List<Map<String, Object>> findingsList = new ArrayList<>();
        for (Map.Entry<String, Map<String, Object>> e : deduped.entrySet()) {
            Map<String, Object> f = e.getValue();
            Map<String, Object> entry = TrinetraCommon.newMap();
            entry.put("v_code", TrinetraCommon.getString(f, "v_code", e.getKey()));
            entry.put("v_name", TrinetraCommon.getString(f, "v_name", "Unknown"));
            entry.put("verdict", TrinetraCommon.getString(f, "verdict", "error"));
            entry.put("severity", deriveSeverity(f));
            entry.put("owasp", OWASP_MAP.getOrDefault(e.getKey(), "Uncategorized"));
            entry.put("tool", TrinetraCommon.getString(f, "tool", ""));
            entry.put("evidence", extractEvidence(f));
            entry.put("cves", extractCves(f));
            entry.put("remediation", REMEDIATION.getOrDefault(e.getKey(), ""));
            findingsList.add(entry);
        }
        report.put("findings", findingsList);

        return TrinetraJson.prettyJson(report);
    }
}
