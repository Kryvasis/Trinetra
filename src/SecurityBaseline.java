import java.util.*;

/**
 * Vendor-neutral Security Baseline Model — PS26155 normalization layer.
 *
 * Converts proprietary CLI (Cisco IOS/Juniper JUNOS/FortiOS/PAN-OS/Generic)
 * into a shared semantic fact model. Framework controls evaluate facts,
 * not vendor syntax directly.
 *
 * This is derived artifact — not part of hash chain genesis, but stored
 * per-device for audit traceability and used by SemanticControlEvaluator.
 */
public class SecurityBaseline {

    public String vendor;
    public String rawVendor;
    public ManagementPlane managementPlane = new ManagementPlane();
    public Authentication authentication = new Authentication();
    public Snmp snmp = new Snmp();
    public Logging logging = new Logging();
    public Cryptography cryptography = new Cryptography();
    public Acl acl = new Acl();
    public NetworkSegmentation networkSegmentation = new NetworkSegmentation();
    public List<String> evidenceLines = new ArrayList<>();
    public String parserVersion = "baseline-v2";

    /** Redact credential-like values before evidence enters JSON, reports or scores. */
    public static String sanitizeEvidence(String value) {
        if (value == null) return "";
        String safe = value;
        safe = safe.replaceAll("(?i)(\\b(?:password|secret|encrypted-password)\\s+(?:\\d+\\s+)?)(\\S+)", "$1[REDACTED]");
        safe = safe.replaceAll("(?i)(\\bsnmp-server\\s+community\\s+)(\\S+)", "$1[REDACTED]");
        safe = safe.replaceAll("(?i)(\\b(?:access[_-]?key|secret[_-]?key|api[_-]?key|token)\\s*[=:]\\s*)(\\S+)", "$1[REDACTED]");
        return safe;
    }

    public static List<String> sanitizeEvidenceList(Collection<String> values) {
        List<String> safe = new ArrayList<>();
        if (values != null) for (String value : values) safe.add(sanitizeEvidence(value));
        return safe;
    }

    public static class ManagementPlane {
        public Boolean sshEnabled;
        public String sshVersion; // "1" | "2" | null
        public List<String> sshEvidence = new ArrayList<>();
        public Boolean telnetEnabled;
        public List<String> telnetEvidence = new ArrayList<>();
        public Boolean httpEnabled;
        public Boolean httpSecureOnly;
        public List<String> httpEvidence = new ArrayList<>();
        public String execTimeout; // e.g. "5 0" , "0 0"
        public List<String> execTimeoutEvidence = new ArrayList<>();
        public Boolean sourceRouteEnabled;
        public List<String> sourceRouteEvidence = new ArrayList<>();
    }

    public static class Authentication {
        public Boolean aaaEnabled;
        public List<String> aaaEvidence = new ArrayList<>();
        public Boolean hasEnableSecret;
        public List<String> enableSecretEvidence = new ArrayList<>();
        public Boolean hasEnablePassword; // insecure
        public List<String> enablePasswordEvidence = new ArrayList<>();
        public Boolean passwordEncryptionEnabled;
        public List<String> passwordEncryptionEvidence = new ArrayList<>();
        public List<User> users = new ArrayList<>();

        public static class User {
            public String name;
            public String authType; // "secret" | "password" | "encrypted-password" | "plain-text-password"
            public String privilege;
            public List<String> evidence = new ArrayList<>();
        }
    }

    public static class Snmp {
        public List<String> versions = new ArrayList<>();
        public List<Community> communities = new ArrayList<>();
        public static class Community {
            public String name;
            public String classification; // "default-public" | "default-private" | "custom"
            public List<String> evidence = new ArrayList<>();
        }
    }

    public static class Logging {
        public Boolean enabled;
        public List<String> hosts = new ArrayList<>();
        public List<String> evidence = new ArrayList<>();
    }

    public static class Cryptography {
        public Boolean strongCryptoEnabled;
        public List<String> enabledCiphers = new ArrayList<>();
        public List<String> weakCiphersFound = new ArrayList<>();
        public List<String> evidence = new ArrayList<>();
        public Boolean tls12OrHigher;
        public List<String> tlsEvidence = new ArrayList<>();
    }

    public static class Acl {
        public Boolean hasGranularAcls;
        public List<AclEntry> entries = new ArrayList<>();
        public List<String> evidence = new ArrayList<>();
        public static class AclEntry {
            public String name;
            public String type; // "standard" | "extended" | "sg" | "nacl" | "sonic_acl"
            public String action; // "permit" | "deny"
            public String evidence;
        }
    }

    public static class NetworkSegmentation {
        /** True when dynamic trunk negotiation is explicitly enabled. */
        public Boolean dynamicTrunkingEnabled;
        /** True when a cloud rule exposes a sensitive management/data port globally. */
        public Boolean publicSensitiveIngress;
        public List<String> evidence = new ArrayList<>();
    }

    /**
     * Apply a governed training-rule mutation to an allow-listed baseline field.
     * Unknown fields and invalid values are rejected instead of using reflection.
     */
    public boolean applyTrainingValue(String field, String rawValue, String evidence) {
        if (field == null || field.isBlank()) return false;
        String value = rawValue == null ? "" : rawValue.trim();
        Boolean bool = parseBoolean(value);
        String safeEvidence = sanitizeEvidence(evidence);
        switch (field.trim().toLowerCase(Locale.ROOT)) {
            case "management_plane.ssh_enabled":
                if (bool == null) return false;
                managementPlane.sshEnabled = bool; managementPlane.sshEvidence.add(safeEvidence); break;
            case "management_plane.ssh_version":
                if (value.isBlank()) return false;
                managementPlane.sshVersion = value; managementPlane.sshEnabled = true; managementPlane.sshEvidence.add(safeEvidence); break;
            case "management_plane.telnet_enabled":
                if (bool == null) return false;
                managementPlane.telnetEnabled = bool; managementPlane.telnetEvidence.add(safeEvidence); break;
            case "management_plane.http_enabled":
                if (bool == null) return false;
                managementPlane.httpEnabled = bool; managementPlane.httpEvidence.add(safeEvidence); break;
            case "management_plane.http_secure_only":
                if (bool == null) return false;
                managementPlane.httpSecureOnly = bool; managementPlane.httpEvidence.add(safeEvidence); break;
            case "management_plane.exec_timeout":
                if (value.isBlank()) return false;
                managementPlane.execTimeout = value; managementPlane.execTimeoutEvidence.add(safeEvidence); break;
            case "management_plane.source_route_enabled":
                if (bool == null) return false;
                managementPlane.sourceRouteEnabled = bool; managementPlane.sourceRouteEvidence.add(safeEvidence); break;
            case "authentication.aaa_enabled":
                if (bool == null) return false;
                authentication.aaaEnabled = bool; authentication.aaaEvidence.add(safeEvidence); break;
            case "authentication.has_enable_secret":
                if (bool == null) return false;
                authentication.hasEnableSecret = bool; authentication.enableSecretEvidence.add(safeEvidence); break;
            case "authentication.has_enable_password":
                if (bool == null) return false;
                authentication.hasEnablePassword = bool; authentication.enablePasswordEvidence.add(safeEvidence); break;
            case "authentication.password_encryption_enabled":
                if (bool == null) return false;
                authentication.passwordEncryptionEnabled = bool; authentication.passwordEncryptionEvidence.add(safeEvidence); break;
            case "logging.enabled":
                if (bool == null) return false;
                logging.enabled = bool; logging.evidence.add(safeEvidence); break;
            case "cryptography.strong_crypto_enabled":
                if (bool == null) return false;
                cryptography.strongCryptoEnabled = bool; cryptography.evidence.add(safeEvidence); break;
            case "cryptography.tls12_or_higher":
                if (bool == null) return false;
                cryptography.tls12OrHigher = bool; cryptography.tlsEvidence.add(safeEvidence); break;
            case "acl.has_granular_acls":
                if (bool == null) return false;
                acl.hasGranularAcls = bool; acl.evidence.add(safeEvidence); break;
            case "network_segmentation.dynamic_trunking_enabled":
                if (bool == null) return false;
                networkSegmentation.dynamicTrunkingEnabled = bool; networkSegmentation.evidence.add(safeEvidence); break;
            case "network_segmentation.public_sensitive_ingress":
                if (bool == null) return false;
                networkSegmentation.publicSensitiveIngress = bool; networkSegmentation.evidence.add(safeEvidence); break;
            default:
                return false;
        }
        evidenceLines.add(safeEvidence);
        return true;
    }

    private static Boolean parseBoolean(String value) {
        if ("true".equalsIgnoreCase(value) || "enabled".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value) || "1".equals(value)) return true;
        if ("false".equalsIgnoreCase(value) || "disabled".equalsIgnoreCase(value) || "no".equalsIgnoreCase(value) || "0".equals(value)) return false;
        return null;
    }

    /** Serialize to map for JSON persistence */
    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("vendor", vendor);
        m.put("raw_vendor", rawVendor);
        m.put("parser_version", parserVersion);
        Map<String, Object> mp = new LinkedHashMap<>();
        mp.put("ssh_enabled", managementPlane.sshEnabled);
        mp.put("ssh_version", managementPlane.sshVersion);
        mp.put("ssh_evidence", sanitizeEvidenceList(managementPlane.sshEvidence));
        mp.put("telnet_enabled", managementPlane.telnetEnabled);
        mp.put("telnet_evidence", sanitizeEvidenceList(managementPlane.telnetEvidence));
        mp.put("http_enabled", managementPlane.httpEnabled);
        mp.put("http_secure_only", managementPlane.httpSecureOnly);
        mp.put("http_evidence", sanitizeEvidenceList(managementPlane.httpEvidence));
        mp.put("exec_timeout", managementPlane.execTimeout);
        mp.put("exec_timeout_evidence", sanitizeEvidenceList(managementPlane.execTimeoutEvidence));
        mp.put("source_route_enabled", managementPlane.sourceRouteEnabled);
        mp.put("source_route_evidence", sanitizeEvidenceList(managementPlane.sourceRouteEvidence));
        m.put("management_plane", mp);

        Map<String, Object> auth = new LinkedHashMap<>();
        auth.put("aaa_enabled", authentication.aaaEnabled);
        auth.put("aaa_evidence", sanitizeEvidenceList(authentication.aaaEvidence));
        auth.put("has_enable_secret", authentication.hasEnableSecret);
        auth.put("enable_secret_evidence", sanitizeEvidenceList(authentication.enableSecretEvidence));
        auth.put("has_enable_password", authentication.hasEnablePassword);
        auth.put("enable_password_evidence", sanitizeEvidenceList(authentication.enablePasswordEvidence));
        auth.put("password_encryption_enabled", authentication.passwordEncryptionEnabled);
        auth.put("password_encryption_evidence", sanitizeEvidenceList(authentication.passwordEncryptionEvidence));
        List<Map<String, Object>> users = new ArrayList<>();
        for (Authentication.User u : authentication.users) {
            Map<String, Object> um = new LinkedHashMap<>();
            um.put("name", u.name);
            um.put("auth_type", u.authType);
            um.put("privilege", u.privilege);
            um.put("evidence", sanitizeEvidenceList(u.evidence));
            users.add(um);
        }
        auth.put("users", users);
        m.put("authentication", auth);

        Map<String, Object> snmpMap = new LinkedHashMap<>();
        snmpMap.put("versions", new ArrayList<>(snmp.versions));
        List<Map<String, Object>> comms = new ArrayList<>();
        for (Snmp.Community c : snmp.communities) {
            Map<String, Object> cm = new LinkedHashMap<>();
            cm.put("name", c.name == null || c.name.isBlank() ? "" : "[REDACTED]");
            cm.put("classification", c.classification);
            cm.put("evidence", sanitizeEvidenceList(c.evidence));
            comms.add(cm);
        }
        snmpMap.put("communities", comms);
        m.put("snmp", snmpMap);

        Map<String, Object> log = new LinkedHashMap<>();
        log.put("enabled", logging.enabled);
        log.put("hosts", new ArrayList<>(logging.hosts));
        log.put("evidence", sanitizeEvidenceList(logging.evidence));
        m.put("logging", log);

        Map<String, Object> crypto = new LinkedHashMap<>();
        crypto.put("strong_crypto_enabled", cryptography.strongCryptoEnabled);
        crypto.put("enabled_ciphers", new ArrayList<>(cryptography.enabledCiphers));
        crypto.put("weak_ciphers_found", new ArrayList<>(cryptography.weakCiphersFound));
        crypto.put("evidence", sanitizeEvidenceList(cryptography.evidence));
        crypto.put("tls12_or_higher", cryptography.tls12OrHigher);
        crypto.put("tls_evidence", sanitizeEvidenceList(cryptography.tlsEvidence));
        m.put("cryptography", crypto);

        Map<String, Object> aclMap = new LinkedHashMap<>();
        aclMap.put("has_granular_acls", acl.hasGranularAcls);
        aclMap.put("evidence", sanitizeEvidenceList(acl.evidence));
        List<Map<String, Object>> aclEntries = new ArrayList<>();
        for (Acl.AclEntry e : acl.entries) {
            Map<String, Object> em = new LinkedHashMap<>();
            em.put("name", e.name);
            em.put("type", e.type);
            em.put("action", e.action);
            em.put("evidence", sanitizeEvidence(e.evidence));
            aclEntries.add(em);
        }
        aclMap.put("entries", aclEntries);
        m.put("acl", aclMap);

        Map<String, Object> segmentation = new LinkedHashMap<>();
        segmentation.put("dynamic_trunking_enabled", networkSegmentation.dynamicTrunkingEnabled);
        segmentation.put("public_sensitive_ingress", networkSegmentation.publicSensitiveIngress);
        segmentation.put("evidence", sanitizeEvidenceList(networkSegmentation.evidence));
        m.put("network_segmentation", segmentation);

        m.put("evidence_lines", sanitizeEvidenceList(evidenceLines));
        return m;
    }

    @SuppressWarnings("unchecked")
    public static SecurityBaseline fromMap(Map<String, Object> m) {
        SecurityBaseline b = new SecurityBaseline();
        if (m == null) return b;
        b.vendor = TrinetraCommon.getString(m, "vendor", "");
        b.rawVendor = TrinetraCommon.getString(m, "raw_vendor", "");
        b.parserVersion = TrinetraCommon.getString(m, "parser_version", "baseline-v1");
        Object mpObj = m.get("management_plane");
        if (mpObj instanceof Map) {
            Map<String, Object> mp = (Map<String, Object>) mpObj;
            b.managementPlane.sshEnabled = (Boolean) mp.get("ssh_enabled");
            b.managementPlane.sshVersion = (String) mp.get("ssh_version");
            b.managementPlane.sshEvidence = toStringList(mp.get("ssh_evidence"));
            b.managementPlane.telnetEnabled = (Boolean) mp.get("telnet_enabled");
            b.managementPlane.telnetEvidence = toStringList(mp.get("telnet_evidence"));
            b.managementPlane.httpEnabled = (Boolean) mp.get("http_enabled");
            b.managementPlane.httpSecureOnly = (Boolean) mp.get("http_secure_only");
            b.managementPlane.httpEvidence = toStringList(mp.get("http_evidence"));
            b.managementPlane.execTimeout = (String) mp.get("exec_timeout");
            b.managementPlane.execTimeoutEvidence = toStringList(mp.get("exec_timeout_evidence"));
            b.managementPlane.sourceRouteEnabled = (Boolean) mp.get("source_route_enabled");
            b.managementPlane.sourceRouteEvidence = toStringList(mp.get("source_route_evidence"));
        }
        Object authObj = m.get("authentication");
        if (authObj instanceof Map) {
            Map<String, Object> auth = (Map<String, Object>) authObj;
            b.authentication.aaaEnabled = (Boolean) auth.get("aaa_enabled");
            b.authentication.aaaEvidence = toStringList(auth.get("aaa_evidence"));
            b.authentication.hasEnableSecret = (Boolean) auth.get("has_enable_secret");
            b.authentication.enableSecretEvidence = toStringList(auth.get("enable_secret_evidence"));
            b.authentication.hasEnablePassword = (Boolean) auth.get("has_enable_password");
            b.authentication.enablePasswordEvidence = toStringList(auth.get("enable_password_evidence"));
            b.authentication.passwordEncryptionEnabled = (Boolean) auth.get("password_encryption_enabled");
            b.authentication.passwordEncryptionEvidence = toStringList(auth.get("password_encryption_evidence"));
            Object usersObj = auth.get("users");
            if (usersObj instanceof List) {
                for (Object o : (List<?>) usersObj) {
                    if (o instanceof Map) {
                        Map<String, Object> um = (Map<String, Object>) o;
                        Authentication.User u = new Authentication.User();
                        u.name = TrinetraCommon.getString(um, "name", "");
                        u.authType = TrinetraCommon.getString(um, "auth_type", "");
                        u.privilege = TrinetraCommon.getString(um, "privilege", "");
                        u.evidence = toStringList(um.get("evidence"));
                        b.authentication.users.add(u);
                    }
                }
            }
        }
        Object snmpObj = m.get("snmp");
        if (snmpObj instanceof Map) {
            Map<String, Object> sm = (Map<String, Object>) snmpObj;
            b.snmp.versions = toStringList(sm.get("versions"));
            Object commsObj = sm.get("communities");
            if (commsObj instanceof List) {
                for (Object o : (List<?>) commsObj) {
                    if (o instanceof Map) {
                        Map<String, Object> cm = (Map<String, Object>) o;
                        Snmp.Community c = new Snmp.Community();
                        c.name = TrinetraCommon.getString(cm, "name", "");
                        c.classification = TrinetraCommon.getString(cm, "classification", "");
                        c.evidence = toStringList(cm.get("evidence"));
                        b.snmp.communities.add(c);
                    }
                }
            }
        }
        Object logObj = m.get("logging");
        if (logObj instanceof Map) {
            Map<String, Object> lm = (Map<String, Object>) logObj;
            b.logging.enabled = (Boolean) lm.get("enabled");
            b.logging.hosts = toStringList(lm.get("hosts"));
            b.logging.evidence = toStringList(lm.get("evidence"));
        }
        Object cryptoObj = m.get("cryptography");
        if (cryptoObj instanceof Map) {
            Map<String, Object> cm = (Map<String, Object>) cryptoObj;
            b.cryptography.strongCryptoEnabled = (Boolean) cm.get("strong_crypto_enabled");
            b.cryptography.enabledCiphers = toStringList(cm.get("enabled_ciphers"));
            b.cryptography.weakCiphersFound = toStringList(cm.get("weak_ciphers_found"));
            b.cryptography.evidence = toStringList(cm.get("evidence"));
            b.cryptography.tls12OrHigher = (Boolean) cm.get("tls12_or_higher");
            b.cryptography.tlsEvidence = toStringList(cm.get("tls_evidence"));
        }
        Object aclObj = m.get("acl");
        if (aclObj instanceof Map) {
            Map<String, Object> am = (Map<String, Object>) aclObj;
            b.acl.hasGranularAcls = (Boolean) am.get("has_granular_acls");
            b.acl.evidence = toStringList(am.get("evidence"));
            Object entriesObj = am.get("entries");
            if (entriesObj instanceof List) {
                for (Object o : (List<?>) entriesObj) {
                    if (o instanceof Map) {
                        Map<String, Object> em = (Map<String, Object>) o;
                        Acl.AclEntry e = new Acl.AclEntry();
                        e.name = TrinetraCommon.getString(em, "name", "");
                        e.type = TrinetraCommon.getString(em, "type", "");
                        e.action = TrinetraCommon.getString(em, "action", "");
                        e.evidence = TrinetraCommon.getString(em, "evidence", "");
                        b.acl.entries.add(e);
                    }
                }
            }
        }
        Object segmentationObj = m.get("network_segmentation");
        if (segmentationObj instanceof Map) {
            Map<String, Object> sm = (Map<String, Object>) segmentationObj;
            b.networkSegmentation.dynamicTrunkingEnabled = (Boolean) sm.get("dynamic_trunking_enabled");
            b.networkSegmentation.publicSensitiveIngress = (Boolean) sm.get("public_sensitive_ingress");
            b.networkSegmentation.evidence = toStringList(sm.get("evidence"));
        }
        b.evidenceLines = toStringList(m.get("evidence_lines"));
        return b;
    }

    private static List<String> toStringList(Object o) {
        List<String> out = new ArrayList<>();
        if (o instanceof List) {
            for (Object e : (List<?>) o) if (e != null) out.add(String.valueOf(e));
        }
        return out;
    }
}
