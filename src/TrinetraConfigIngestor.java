import java.nio.file.*;
import java.util.*;
import java.util.regex.*;

/**
 * Config-file ingestion path — repoints VendorConnector parsing at file content.
 * Primary path for PS26155: upload file → parse → compliance checks → score → report.
 * Live collection remains optional (ingestion_method="live_fetch").
 *
 * Keeps core engine (parsing, normalization, scoring, hash-chain, narrative) reusable:
 * same VendorConnector.normalizeCommand and same TrinetraStat.DecisionEngine are used,
 * just fed from file content instead of live SSH runCommand output.
 */
public class TrinetraConfigIngestor {

    // Known config patterns per vendor — minimal set covering the 8 CIS seed controls
    // Each pattern maps to a V-code check. This is the "existing VendorConnector logic" repurposed.
    private static final Map<String, Map<String, String>> KNOWN_PATTERNS = new LinkedHashMap<>();
    static {
        // Cisco: each entry is regex -> V-code
        Map<String, String> cisco = new LinkedHashMap<>();
        cisco.put("(?i)enable\\s+secret", "V-013"); // weak/default credentials - AAA
        cisco.put("(?i)username\\s+.*\\s+secret", "V-013");
        cisco.put("(?i)username\\s+.*\\s+password", "V-013");
        cisco.put("(?i)ip\\s+ssh\\s+version\\s+1", "V-006"); // weak TLS/SSH
        cisco.put("(?i)ip\\s+ssh\\s+time-out", "V-071"); // SSH timeout CIS 2.1.1.1.4
        cisco.put("(?i)exec-timeout", "V-071"); // exec/idle timeout CIS 1.2.6
        cisco.put("(?i)aaa\\s+new-model", "V-013"); // AAA CIS 1.1.1
        cisco.put("(?i)snmp-server\\s+community\\s+(public|private)", "V-057"); // SNMP CIS 1.4.6
        cisco.put("(?i)snmp-server\\s+community", "V-107");
        cisco.put("(?i)logging\\s+.*", "V-058"); // logging CIS 1.5.1
        cisco.put("(?i)transport\\s+input\\s+.*telnet", "V-071"); // insecure mgmt CIS 4.6
        cisco.put("(?i)ip\\s+http\\s+server", "V-071");
        cisco.put("(?i)service\\s+password-encryption", "V-013");
        cisco.put("(?i)ntp\\s+server", "V-058");
        KNOWN_PATTERNS.put("Cisco", cisco);

        Map<String, String> juniper = new LinkedHashMap<>();
        juniper.put("(?i)set\\s+system\\s+host-name", "V-003");
        juniper.put("(?i)set\\s+system\\s+login", "V-013");
        juniper.put("(?i)set\\s+system\\s+services\\s+ssh", "V-006");
        juniper.put("(?i)set\\s+system\\s+syslog", "V-058");
        juniper.put("(?i)set\\s+snmp\\s+community", "V-057");
        juniper.put("(?i)set\\s+system\\s+services\\s+telnet", "V-071");
        juniper.put("(?i)set\\s+system\\s+login\\s+idle-timeout", "V-071");
        KNOWN_PATTERNS.put("Juniper", juniper);

        Map<String, String> generic = new LinkedHashMap<>();
        generic.put("(?i)password", "V-013");
        generic.put("(?i)telnet", "V-071");
        generic.put("(?i)snmp.*public", "V-057");
        generic.put("(?i)logging", "V-058");
        KNOWN_PATTERNS.put("Generic", generic);
    }

    public static class IngestResult {
        public final String deviceId;
        public final String vendor;
        public final String ingestionMethod;
        public final int totalChecks;
        public final int passed;
        public final int failed;
        public final List<String> unrecognizedLines;
        public final List<Map<String, Object>> findings;

        public IngestResult(String deviceId, String vendor, String method, int total, int passed, int failed, List<String> unrecognized, List<Map<String, Object>> findings) {
            this.deviceId = deviceId;
            this.vendor = vendor;
            this.ingestionMethod = method;
            this.totalChecks = total;
            this.passed = passed;
            this.failed = failed;
            this.unrecognizedLines = unrecognized;
            this.findings = findings;
        }
    }

    /**
     * Auto-detect vendor from config content.
     * Checks for Cisco vs Juniper header patterns.
     */
    public static String autoDetectVendor(String configContent) {
        if (configContent == null || configContent.isBlank()) return "Generic";
        String lower = configContent.toLowerCase();
        // Juniper: "set system" is distinctive
        if (lower.contains("set system") || lower.contains("junos") || lower.contains("juniper")) {
            return "Juniper";
        }
        // Cisco: "hostname", "interface", "enable secret", "cisco"
        if (lower.contains("hostname") || lower.contains("interface ") || lower.contains("cisco") || lower.contains("enable secret") || lower.contains("line vty") || lower.contains("ip ssh")) {
            return "Cisco";
        }
        return "Generic";
    }

    /**
     * Ingest config file for a device: parse, run checks, store findings, track ingestion_method and unrecognized lines.
     * Returns IngestResult with summary.
     * Overload without hardware metadata delegates to full version with blank details.
     */
    public static IngestResult ingest(String sessionName, String deviceId, String vendorHint, String configContent, String filename) {
        return ingest(sessionName, deviceId, vendorHint, configContent, filename, null, null, null);
    }

    /**
     * Full ingest with distinct hardware metadata (PS Deliverable 4 + item 8 OS-version).
     * serialNumber, hardwareModel, osVersion are optional free-text; osVersion is also
     * auto-detected via lightweight header scan when blank (metadata-level awareness, not parsing branch).
     */
    public static IngestResult ingest(String sessionName, String deviceId, String vendorHint, String configContent, String filename,
                                      String serialNumber, String hardwareModel, String osVersion) {
        return ingest(sessionName, deviceId, vendorHint, configContent, filename,
                      serialNumber, hardwareModel, osVersion, "config_upload");
    }

    /** Full ingest with a constrained provenance tag for upload or live collection. */
    public static IngestResult ingest(String sessionName, String deviceId, String vendorHint, String configContent, String filename,
                                      String serialNumber, String hardwareModel, String osVersion, String ingestionMethod) {
        // Reject web documents before changing session metadata or writing artifacts.
        if (configContent != null && Pattern.compile("(?is)^\\s*\\ufeff?\\s*(?:<\\?xml[^>]*>\\s*)?(?:<!--.*?-->\\s*)*(?:<!doctype\\s+html\\b|<html\\b|<head\\b|<body\\b)")
                .matcher(configContent.substring(0, Math.min(configContent.length(), 65536))).find()) {
            throw new IllegalArgumentException("Webpages are not device configurations. Use Website analysis or provide a device export.");
        }
        String sanitized = TrinetraCommon.sanitizeName(sessionName);
        String methodTag = "live_fetch".equals(ingestionMethod) ? "live_fetch" : "config_upload";
        String vendor = vendorHint;
        if (vendor == null || vendor.isBlank() || vendor.equalsIgnoreCase("auto")) {
            vendor = autoDetectVendor(configContent);
        }
        vendor = vendor.trim();
        // ── OS-version lightweight detection (item 8) — header scan only, no parsing branch ──
        String detectedOs = detectOsVersion(configContent, vendor);
        String effectiveOs = (osVersion != null && !osVersion.isBlank()) ? osVersion.trim() : detectedOs;
        // Normalize vendor via registry (ensures Cisco/Juniper canonical)
        VendorConnector connector = VendorConnectorRegistry.resolve(vendor);
        String canonicalVendor = connector.getVendorName();
        // Store device vendor, ingestion method, and distinct metadata
        TrinetraSession.setDeviceVendor(sanitized, deviceId, canonicalVendor);
        TrinetraSession.setDeviceIngestion(sanitized, deviceId, methodTag, filename);
        TrinetraSession.setDeviceDetails(sanitized, deviceId, serialNumber, hardwareModel, effectiveOs);

        // Save config file to artifacts
        try {
            Path artifacts = TrinetraCommon.sessionArtifactsDir(sanitized);
            Files.createDirectories(artifacts);
            String safeDevice = TrinetraCommon.sanitizeName(deviceId);
            Path configPath = artifacts.resolve(safeDevice + "_config.txt");
            if (filename != null && !filename.isBlank()) {
                configPath = artifacts.resolve(TrinetraCommon.sanitizeName(filename));
            }
            TrinetraCommon.atomicWriteFile(configPath, configContent);
            // Also save with device-specific name for traceability
            Path deviceConfig = artifacts.resolve(safeDevice + "_uploaded_config.txt");
            TrinetraCommon.atomicWriteFile(deviceConfig, configContent);
        } catch (Exception e) {
            TrinetraCommon.logWarn("Failed to save config file for " + deviceId + ": " + e.getMessage());
        }

        // Parse: split into lines, classify each
        List<String> lines = configContent != null ? Arrays.asList(configContent.split("\\r?\\n")) : new ArrayList<>();
        List<String> unrecognized = new ArrayList<>();
        List<String> recognized = new ArrayList<>();
        Map<String, String> lineToVcode = new LinkedHashMap<>(); // line -> V-code for scoring

        // Known patterns for this vendor
        Map<String, String> knownForVendor = KNOWN_PATTERNS.getOrDefault(canonicalVendor, KNOWN_PATTERNS.get("Generic"));
        // Also include generic patterns as fallback
        Map<String, String> allKnown = new LinkedHashMap<>(knownForVendor);
        allKnown.putAll(KNOWN_PATTERNS.get("Generic"));

        for (String rawLine : lines) {
            String line = rawLine.trim();
            if (line.isEmpty() || line.startsWith("!") || line.startsWith("#")) continue; // comments/separators
            boolean matched = false;
            // First, check training map (no code change needed)
            VendorTrainingMap.Entry trained = VendorTrainingMap.findMatch(canonicalVendor, line);
            if (trained != null) {
                recognized.add(line);
                // Use the first control's mapped test? For training, we map pattern to a V-code via security_category
                // For simplicity, map trained entries to V-003 (open) or use the first control's test mapping
                // We'll map to the most relevant V-code based on category
                String vcode = mapCategoryToVcode(trained.securityCategory, trained.controlMapping);
                if (vcode != null) lineToVcode.put(line, vcode);
                matched = true;
                continue;
            }
            // Check known patterns
            for (Map.Entry<String, String> e : allKnown.entrySet()) {
                try {
                    if (Pattern.compile(e.getKey(), Pattern.CASE_INSENSITIVE).matcher(line).find()) {
                        recognized.add(line);
                        lineToVcode.put(line, e.getValue());
                        matched = true;
                        break;
                    }
                } catch (Exception ex) {
                    if (line.toLowerCase().contains(e.getKey().toLowerCase())) {
                        recognized.add(line);
                        lineToVcode.put(line, e.getValue());
                        matched = true;
                        break;
                    }
                }
            }
            if (!matched) {
                // Also try VendorConnector.normalizeCommand to see if it recognizes the command
                String normalized = connector.normalizeCommand(line);
                // If normalize changes the line, it was recognized; if not, treat as unrecognized if line looks like config
                // For now, if line contains typical config keywords but didn't match known, flag as unrecognized
                if (line.length() > 3 && line.matches(".*[a-zA-Z].*")) {
                    // Heuristic: if line looks like a config directive (contains letters, maybe spaces) and is not just a hostname, flag
                    // But avoid flagging every unknown line as unrecognized; only flag if it looks like a directive
                    // For demo, flag lines that are not empty and not already recognized and are > 5 chars
                    if (line.length() > 5) {
                        unrecognized.add(line);
                    }
                }
            }
        }

        // Store unrecognized lines per device
        TrinetraSession.setUnrecognizedLines(sanitized, deviceId, unrecognized);

        // Run compliance checks against the config content as a whole
        // For each relevant V-code, evaluate the entire config content.
        // Category 1 controls use config-syntax-native logic (explicit vendor directives);
        // Category 2 controls inherently require live network/runtime state and are
        // returned as manual_review with a distinct, honest detail message.
        // This keeps the live-probe DecisionEngine path (TrinetraStat) untouched.
        TrinetraStat.loadDefinitions();
        List<Map<String, Object>> findings = new ArrayList<>();
        int passed = 0, failed = 0;
        // Score the full PS-required set (15) so Category 2 appears as
        // "requires live verification" rather than vanishing into coverage_gaps.
        // lineToVcode values are included for completeness but the PS set is authoritative.
        Set<String> psRequired = new LinkedHashSet<>(Arrays.asList(
            "V-003","V-005","V-006","V-007","V-008","V-013","V-057","V-058","V-070","V-071","V-087","V-105","V-106","V-107","V-144"
        ));
        Set<String> vcodesToCheck = new LinkedHashSet<>(psRequired);
        vcodesToCheck.addAll(lineToVcode.values());
        // Fallback: also keep the original default set for any non-PS line mappings
        Set<String> defaultChecks = new LinkedHashSet<>(Arrays.asList("V-013", "V-071", "V-006", "V-007", "V-057", "V-058", "V-003"));
        for (String vc : defaultChecks) {
            if (TrinetraStat.isStatCode(vc)) vcodesToCheck.add(vc);
        }

        for (String vcode : vcodesToCheck) {
            TrinetraStat.TestDefinition def = TrinetraStat.getTestDefinition(vcode);
            if (def == null || def.decisionRule == null) continue;
            String rawForCheck = configContent != null ? configContent : "";
            TrinetraStat.Verdict verdict;
            String detail;
            if (isConfigCategory1(vcode)) {
                verdict = evaluateConfigControl(vcode, configContent);
                detail = "config-syntax -> " + verdict + " (config-native check; deterministic from static text)";
            } else if (isConfigCategory2(vcode)) {
                verdict = TrinetraStat.Verdict.MANUAL_REVIEW;
                detail = "requires live network verification — not determinable from static config alone (Category 2 control; run via live probe `trinetra -stat run " + vcode + "` for real pass/fail)";
            } else {
                boolean requiresRuntime = "exit_code_zero".equals(def.decisionRule.evalMethod)
                    || "numeric_threshold".equals(def.decisionRule.evalMethod);
                verdict = requiresRuntime
                    ? TrinetraStat.Verdict.MANUAL_REVIEW
                    : TrinetraStat.DecisionEngine.evaluate(def.decisionRule, rawForCheck, 0);
                detail = requiresRuntime
                    ? "Runtime evidence required; an uploaded configuration cannot establish a command exit code or runtime numeric measurement."
                    : def.decisionRule.evalMethod + " -> " + verdict + " (config-file; verify full configuration and applicability)";
                if (requiresRuntime) {
                    // Overwrite with Category 2 wording when the V-code is known to be live-only
                    // (keeps stub vs architectural distinction clear)
                    detail = "requires live network verification — not determinable from static config alone (Category 2 control; run via live probe `trinetra -stat run " + vcode + "` for real pass/fail)";
                }
            }

            // Build finding similar to TrinetraStat.statRun but with ingestion_method
            Map<String, Object> finding = TrinetraCommon.newMap();
            finding.put("finding_id", UUID.randomUUID().toString());
            finding.put("v_code", vcode);
            finding.put("test_code", vcode);
            finding.put("v_name", def.name);
            finding.put("target", deviceId);
            finding.put("device_id", deviceId);
            finding.put("vendor", canonicalVendor);
            finding.put("ingestion_method", methodTag);
            finding.put("config_filename", filename != null ? filename : deviceId + "_config.txt");
            finding.put("script", "config_ingest:" + vcode);
            finding.put("started_at", TrinetraCommon.nowIso());
            finding.put("ended_at", TrinetraCommon.nowIso());
            finding.put("exit_code", 0);
            finding.put("verdict", verdict.name().toLowerCase());
            finding.put("verdict_detail", detail);
            finding.put("eval_method", def.decisionRule.evalMethod);
            finding.put("pass_criteria", def.decisionRule.passCriteria);
            finding.put("fail_criteria", def.decisionRule.failCriteria);
            finding.put("default_severity", def.defaultSeverity);
            finding.put("category", def.category);
            finding.put("tool", def.tool);
            boolean success = verdict == TrinetraStat.Verdict.PASS;
            finding.put("success", success);
            finding.put("status", success ? "pass" : verdict.name().toLowerCase());
            finding.put("raw_output", rawForCheck.substring(0, Math.min(2000, rawForCheck.length())));
            finding.put("summary", "Config-file check: " + verdict + " for " + vcode);
            finding.put("summary_status", "captured_but_unsummarized");
            finding.put("artifacts", TrinetraCommon.newList());
            finding.put("tags", TrinetraCommon.newList());
            finding.put("engine", "config_ingest");

            // Append to session
            TrinetraSession.appendFinding(sanitized, finding);
            // Also append to normalized_results for scoring
            Map<String, Object> norm = TrinetraCommon.newMap();
            norm.put("device_id", deviceId);
            norm.put("vendor", canonicalVendor);
            norm.put("test_id", vcode);
            norm.put("raw_output", rawForCheck.substring(0, Math.min(2000, rawForCheck.length())));
            norm.put("normalized_result", verdict.name().toLowerCase());
            norm.put("ingestion_method", methodTag);
            TrinetraSession.appendNormalizedResult(sanitized, norm);

            findings.add(finding);
            if (success) passed++; else if (verdict == TrinetraStat.Verdict.FAIL) failed++;
        }

        // Also store a summary finding for unrecognized lines
        if (!unrecognized.isEmpty()) {
            Map<String, Object> uncFinding = TrinetraCommon.newMap();
            uncFinding.put("finding_id", UUID.randomUUID().toString());
            uncFinding.put("v_code", "UNRECOGNIZED");
            uncFinding.put("test_code", "UNRECOGNIZED");
            uncFinding.put("v_name", "Unrecognized config lines");
            uncFinding.put("target", deviceId);
            uncFinding.put("device_id", deviceId);
            uncFinding.put("vendor", canonicalVendor);
            uncFinding.put("ingestion_method", methodTag);
            uncFinding.put("tool", "config_ingest");
            uncFinding.put("script", "config_ingest:unrecognized");
            uncFinding.put("started_at", TrinetraCommon.nowIso());
            uncFinding.put("ended_at", TrinetraCommon.nowIso());
            uncFinding.put("exit_code", 0);
            uncFinding.put("verdict", "manual_review");
            uncFinding.put("verdict_detail", "Unrecognized lines: " + unrecognized.size());
            uncFinding.put("raw_output", String.join("\n", unrecognized));
            uncFinding.put("unrecognized_lines", new ArrayList<>(unrecognized));
            uncFinding.put("status", "manual_review");
            uncFinding.put("success", false);
            TrinetraSession.appendFinding(sanitized, uncFinding);
        }

        TrinetraBrain.updateBrain(sanitized);

        return new IngestResult(deviceId, canonicalVendor, methodTag, findings.size(), passed, failed, unrecognized, findings);
    }

    // ── PS 15-way Classification (Step 1) ──────────────────────────────────
    // Category 1: genuinely determinable from static config text alone.
    // Category 2: inherently requires live network/runtime state — config cannot prove it.
    private static final Set<String> CONFIG_CATEGORY_1 = Set.of(
        "V-003", // open port/unnecessary service — presence of ip http server / telnet / snmp public in config proves unnecessary service is enabled
        "V-006", // weak TLS/SSH version — ip ssh version 1 vs 2 is explicit in config
        "V-013", // weak password policy — enable password vs enable secret, username password vs secret, service password-encryption, aaa new-model
        "V-057", // hardcoded secrets / SNMP community — snmp-server community public/private
        "V-058", // sensitive data in logs — logging host / logging trap presence vs absence
        "V-071", // exposed admin interface — transport input telnet, ip http server, exec-timeout 0 0 vs ssh / no http / timeout 5 0
        "V-107"  // IAM/policy misconfig — username privilege 15 with password vs secret, aaa
        // Note: V-005/007/008/070/087/105/106/144 are Category 2 — see below
    );
    private static final Set<String> CONFIG_CATEGORY_2 = Set.of(
        "V-005", // banner grabbing — requires live nmap -sV banner fetch, not present in config (banner motd is not version disclosure)
        "V-007", // weak cipher — requires live TLS handshake cipher negotiation; config rarely lists explicit weak ciphers
        "V-008", // expired/self-signed cert — requires live openssl s_client fetch
        "V-070", // unpatched OS — requires live version vs CVE DB correlation (config banner only gives version string)
        "V-087", // vulnerable dependencies/SCA — requires filesystem grype/syft scan
        "V-105", // flat network/no segmentation — requires live segmentation probe; ACL presence alone cannot prove reachability
        "V-106", // public cloud storage — requires live cloud API (aws s3api), not device config
        "V-144"  // kernel hardening — requires live host kernel-hardening-checker
    );

    static boolean isConfigCategory1(String vcode) {
        return vcode != null && CONFIG_CATEGORY_1.contains(vcode.toUpperCase());
    }
    static boolean isConfigCategory2(String vcode) {
        return vcode != null && CONFIG_CATEGORY_2.contains(vcode.toUpperCase());
    }

    /**
     * Config-syntax-native evaluation for Category 1 controls.
     * Uses explicit vendor directive patterns (Cisco IOS/Juniper JUNOS), not probe-output phrases.
     * Returns PASS/FAIL/MANUAL_REVIEW — never fabricates for Category 2.
     * Verified against Cisco IOS XE 17.x and JUNOS 20.4 documentation: directive names are real.
     */
    static TrinetraStat.Verdict evaluateConfigControl(String vcode, String configContent) {
        if (vcode == null || configContent == null) return TrinetraStat.Verdict.MANUAL_REVIEW;
        String cfg = configContent;
        String lower = cfg.toLowerCase();
        // Split into trimmed non-comment lines for precise "no ..." handling
        List<String> lines = new ArrayList<>();
        for (String raw : cfg.split("\\r?\\n")) {
            String t = raw.trim();
            if (t.isEmpty() || t.startsWith("!") || t.startsWith("#")) continue;
            lines.add(t);
        }
        String joinedLower = lower; // for substring checks
        switch (vcode.toUpperCase()) {
            case "V-013": {
                // Insecure: enable password (plaintext) or username ... password (not secret)
                boolean insecure = Pattern.compile("(?i)^\\s*enable\\s+password\\b", Pattern.MULTILINE).matcher(cfg).find()
                    || Pattern.compile("(?i)username\\s+\\S+\\s+password\\s", Pattern.MULTILINE).matcher(cfg).find();
                if (insecure) return TrinetraStat.Verdict.FAIL;
                boolean secure = Pattern.compile("(?i)enable\\s+secret", Pattern.MULTILINE).matcher(cfg).find()
                    || Pattern.compile("(?i)username\\s+\\S+\\s+secret\\b", Pattern.MULTILINE).matcher(cfg).find()
                    || Pattern.compile("(?i)service\\s+password-encryption", Pattern.MULTILINE).matcher(cfg).find()
                    || Pattern.compile("(?i)aaa\\s+new-model", Pattern.MULTILINE).matcher(cfg).find();
                // Juniper: encrypted-password is secure, plain-text-password is insecure
                if (lower.contains("plain-text-password")) return TrinetraStat.Verdict.FAIL;
                if (lower.contains("encrypted-password")) secure = true;
                if (secure) return TrinetraStat.Verdict.PASS;
                return TrinetraStat.Verdict.MANUAL_REVIEW;
            }
            case "V-057": {
                boolean insecure = false;
                for (String l : lines) {
                    String ll = l.toLowerCase();
                    if (ll.startsWith("no ")) continue; // "no snmp-server community public" is remediation, not violation
                    if (ll.matches(".*snmp-server\\s+community\\s+(public|private)\\b.*")) insecure = true;
                    if (ll.matches(".*set\\s+snmp\\s+community\\s+public\\b.*")) insecure = true;
                    if (ll.matches(".*set\\s+snmp\\s+community\\s+private\\b.*")) insecure = true;
                }
                if (insecure) return TrinetraStat.Verdict.FAIL;
                if (!cfg.isBlank()) return TrinetraStat.Verdict.PASS;
                return TrinetraStat.Verdict.MANUAL_REVIEW;
            }
            case "V-071": {
                // Insecure: transport input telnet, ip http server (without no), exec-timeout 0 0
                boolean insecure = false;
                for (String l : lines) {
                    String ll = l.toLowerCase();
                    if (ll.matches(".*transport\\s+input\\s+.*\\btelnet\\b.*")) insecure = true;
                    if (ll.matches("^\\s*ip\\s+http\\s+server\\s*$")) insecure = true; // exactly ip http server, not "no ..."
                    if (ll.matches(".*exec-timeout\\s+0\\s+0.*")) insecure = true;
                    if (ll.contains("set system services telnet")) insecure = true; // Juniper
                }
                if (insecure) return TrinetraStat.Verdict.FAIL;
                boolean secure = false;
                for (String l : lines) {
                    String ll = l.toLowerCase();
                    if (ll.contains("transport input ssh") && !ll.contains("telnet")) secure = true;
                    if (ll.matches("^\\s*no\\s+ip\\s+http\\s+server\\s*$")) secure = true;
                    if (ll.matches(".*exec-timeout\\s+[1-9].*")) secure = true;
                    if (ll.contains("set system services ssh")) secure = true;
                }
                if (secure) return TrinetraStat.Verdict.PASS;
                return TrinetraStat.Verdict.MANUAL_REVIEW;
            }
            case "V-006": {
                boolean insecure = Pattern.compile("(?i)ip\\s+ssh\\s+version\\s+1\\b").matcher(cfg).find()
                    || lower.contains("set system services ssh protocol-version v1");
                if (insecure) return TrinetraStat.Verdict.FAIL;
                boolean secure = Pattern.compile("(?i)ip\\s+ssh\\s+version\\s+2\\b").matcher(cfg).find()
                    || lower.contains("protocol-version v2");
                if (secure) return TrinetraStat.Verdict.PASS;
                return TrinetraStat.Verdict.MANUAL_REVIEW;
            }
            case "V-003": {
                // Unnecessary service: ip http server, snmp public/private, telnet, ip source-route, service pad
                boolean insecure = false;
                for (String l : lines) {
                    String ll = l.toLowerCase();
                    if (ll.startsWith("no ")) continue;
                    if (ll.matches("^\\s*ip\\s+http\\s+server\\s*$")) insecure = true;
                    if (ll.matches(".*snmp-server\\s+community\\s+(public|private).*")) insecure = true;
                    if (ll.matches(".*transport\\s+input\\s+.*telnet.*")) insecure = true;
                    if (ll.matches("^\\s*ip\\s+source-route\\s*$")) insecure = true;
                    if (ll.matches("^\\s*service\\s+pad\\s*$")) insecure = true;
                    if (ll.contains("set snmp community public") || ll.contains("set snmp community private")) insecure = true;
                }
                if (insecure) return TrinetraStat.Verdict.FAIL;
                boolean secure = false;
                for (String l : lines) {
                    String ll = l.toLowerCase();
                    if (ll.matches("^\\s*no\\s+ip\\s+http\\s+server\\s*$")) secure = true;
                    if (ll.matches("^\\s*no\\s+ip\\s+source-route\\s*$")) secure = true;
                    if (ll.matches("^\\s*no\\s+service\\s+pad\\s*$")) secure = true;
                }
                if (secure) return TrinetraStat.Verdict.PASS;
                if (!cfg.isBlank() && !insecure) return TrinetraStat.Verdict.PASS;
                return TrinetraStat.Verdict.MANUAL_REVIEW;
            }
            case "V-058": {
                boolean hasLogging = false;
                boolean noLogging = false;
                for (String l : lines) {
                    String ll = l.toLowerCase();
                    if (ll.startsWith("no ")) {
                        if (ll.contains("logging host")) noLogging = true;
                        continue;
                    }
                    if (ll.matches(".*logging\\s+host\\b.*") || ll.matches(".*logging\\s+trap\\b.*") || ll.contains("set system syslog")) hasLogging = true;
                }
                if (hasLogging) return TrinetraStat.Verdict.PASS;
                if (noLogging || (!hasLogging && !cfg.isBlank())) return TrinetraStat.Verdict.FAIL;
                return TrinetraStat.Verdict.MANUAL_REVIEW;
            }
            case "V-107": {
                boolean insecure = false;
                for (String l : lines) {
                    String ll = l.toLowerCase();
                    if (ll.startsWith("no ")) continue;
                    if (ll.matches(".*username\\s+\\S+\\s+password\\s.*")) insecure = true;
                    if (ll.contains("plain-text-password") && ll.contains("class super-user")) insecure = true;
                }
                // Also insecure if any username line has password not secret
                if (!insecure) {
                    boolean hasPassword = false;
                    boolean hasSecret = false;
                    for (String l : lines) {
                        String ll = l.toLowerCase();
                        if (ll.startsWith("no ")) continue;
                        if (ll.matches(".*username\\s+\\S+\\s+.*password\\s.*")) hasPassword = true;
                        if (ll.matches(".*username\\s+\\S+\\s+.*secret\\b.*")) hasSecret = true;
                    }
                    if (hasPassword && !hasSecret) insecure = true;
                }
                if (insecure) return TrinetraStat.Verdict.FAIL;
                boolean secure = false;
                for (String l : lines) {
                    String ll = l.toLowerCase();
                    if (ll.startsWith("no ")) continue;
                    if (ll.matches(".*username\\s+\\S+\\s+privilege\\s+\\d+\\s+secret\\b.*")) secure = true;
                    if (ll.contains("encrypted-password") && ll.contains("class operator")) secure = true;
                    if (ll.matches(".*username\\s+\\S+\\s+secret\\b.*")) secure = true;
                }
                if (lower.contains("aaa new-model") && lower.contains("username") && !insecure) secure = true;
                if (secure) return TrinetraStat.Verdict.PASS;
                return TrinetraStat.Verdict.MANUAL_REVIEW;
            }
            default:
                return TrinetraStat.Verdict.MANUAL_REVIEW;
        }
    }

    /**
     * Lightweight OS-version detection — scans first ~2000 chars for common
     * version-banner strings. Returns empty string when no banner found.
     * This is metadata-level awareness only; core parsing does NOT branch on it.
     */
    static String detectOsVersion(String configContent, String vendorHint) {
        if (configContent == null || configContent.isBlank()) return "";
        String head = configContent.length() > 4000 ? configContent.substring(0, 4000) : configContent;
        String lower = head.toLowerCase();
        // IOS XE — e.g. "Cisco IOS XE Software, Version 17.6.5" or "ios-xe"
        if (lower.contains("ios xe") || lower.contains("ios-xe") || lower.contains("version 17.") || lower.contains("version 16.")) {
            // Try to extract version token
            java.util.regex.Matcher m = Pattern.compile("version\\s+([\\d\\.\\(\\)A-Za-z]+)", Pattern.CASE_INSENSITIVE).matcher(head);
            if (m.find()) return "IOS XE " + m.group(1).trim();
            return "IOS XE";
        }
        // NX-OS — e.g. "Cisco Nexus Operating System (NX-OS) Software, Version 9.3(9)"
        if (lower.contains("nx-os") || lower.contains("nexus") || lower.contains("nxos")) {
            java.util.regex.Matcher m = Pattern.compile("version\\s+([\\d\\.\\(\\)]+)", Pattern.CASE_INSENSITIVE).matcher(head);
            if (m.find()) return "NX-OS " + m.group(1).trim();
            return "NX-OS";
        }
        // JUNOS — e.g. "JUNOS 20.4R3-S2.4" or "junos"
        if (lower.contains("junos") || lower.contains("juniper")) {
            java.util.regex.Matcher m = Pattern.compile("junos\\s+([\\d\\.R\\-S]+)", Pattern.CASE_INSENSITIVE).matcher(head);
            if (m.find()) return "JUNOS " + m.group(1).trim();
            if (lower.contains("junos")) return "JUNOS";
            return "JUNOS";
        }
        // Generic IOS — e.g. "Cisco IOS Software, Version 15.9(3)M6"
        if (lower.contains("cisco ios software") || lower.contains("cisco ios ")) {
            java.util.regex.Matcher m = Pattern.compile("version\\s+([\\d\\.\\(\\)A-Za-z]+)", Pattern.CASE_INSENSITIVE).matcher(head);
            if (m.find()) return "IOS " + m.group(1).trim();
            return "IOS";
        }
        // Generic version fallback: look for Cisco/Juniper version line
        java.util.regex.Matcher m = Pattern.compile("version\\s+([\\d\\.]+)", Pattern.CASE_INSENSITIVE).matcher(head);
        if (m.find() && (lower.contains("cisco") || lower.contains("juniper"))) {
            return (vendorHint != null ? vendorHint + " " : "") + m.group(1).trim();
        }
        return "";
    }

    private static String mapCategoryToVcode(String category, List<String> controls) {
        if (category == null) return null;
        String lower = category.toLowerCase();
        if (lower.contains("credential") || lower.contains("password") || lower.contains("auth")) return "V-013";
        if (lower.contains("tls") || lower.contains("cipher") || lower.contains("crypto")) return "V-006";
        if (lower.contains("admin") || lower.contains("telnet") || lower.contains("http")) return "V-071";
        if (lower.contains("ssh") && lower.contains("timeout")) return "V-071";
        if (lower.contains("snmp")) return "V-057";
        if (lower.contains("log")) return "V-058";
        if (controls != null && !controls.isEmpty()) {
            String first = controls.get(0).toLowerCase();
            if (first.contains("4.7")) return "V-013";
            if (first.contains("3.10")) return "V-006";
            if (first.contains("4.6")) return "V-071";
            if (first.contains("2.1.1")) return "V-071";
            if (first.contains("1.1.1")) return "V-013";
            if (first.contains("1.4.6")) return "V-057";
            if (first.contains("1.5")) return "V-058";
        }
        return "V-003"; // default
    }
}
