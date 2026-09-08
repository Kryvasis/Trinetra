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
    public List<String> evidenceLines = new ArrayList<>();
    public String parserVersion = "baseline-v1";

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

    /** Serialize to map for JSON persistence */
    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("vendor", vendor);
        m.put("raw_vendor", rawVendor);
        m.put("parser_version", parserVersion);
        Map<String, Object> mp = new LinkedHashMap<>();
        mp.put("ssh_enabled", managementPlane.sshEnabled);
        mp.put("ssh_version", managementPlane.sshVersion);
        mp.put("ssh_evidence", new ArrayList<>(managementPlane.sshEvidence));
        mp.put("telnet_enabled", managementPlane.telnetEnabled);
        mp.put("telnet_evidence", new ArrayList<>(managementPlane.telnetEvidence));
        mp.put("http_enabled", managementPlane.httpEnabled);
        mp.put("http_secure_only", managementPlane.httpSecureOnly);
        mp.put("http_evidence", new ArrayList<>(managementPlane.httpEvidence));
        mp.put("exec_timeout", managementPlane.execTimeout);
        mp.put("exec_timeout_evidence", new ArrayList<>(managementPlane.execTimeoutEvidence));
        mp.put("source_route_enabled", managementPlane.sourceRouteEnabled);
        mp.put("source_route_evidence", new ArrayList<>(managementPlane.sourceRouteEvidence));
        m.put("management_plane", mp);

        Map<String, Object> auth = new LinkedHashMap<>();
        auth.put("aaa_enabled", authentication.aaaEnabled);
        auth.put("aaa_evidence", new ArrayList<>(authentication.aaaEvidence));
        auth.put("has_enable_secret", authentication.hasEnableSecret);
        auth.put("enable_secret_evidence", new ArrayList<>(authentication.enableSecretEvidence));
        auth.put("has_enable_password", authentication.hasEnablePassword);
        auth.put("enable_password_evidence", new ArrayList<>(authentication.enablePasswordEvidence));
        auth.put("password_encryption_enabled", authentication.passwordEncryptionEnabled);
        auth.put("password_encryption_evidence", new ArrayList<>(authentication.passwordEncryptionEvidence));
        List<Map<String, Object>> users = new ArrayList<>();
        for (Authentication.User u : authentication.users) {
            Map<String, Object> um = new LinkedHashMap<>();
            um.put("name", u.name);
            um.put("auth_type", u.authType);
            um.put("privilege", u.privilege);
            um.put("evidence", new ArrayList<>(u.evidence));
            users.add(um);
        }
        auth.put("users", users);
        m.put("authentication", auth);

        Map<String, Object> snmpMap = new LinkedHashMap<>();
        snmpMap.put("versions", new ArrayList<>(snmp.versions));
        List<Map<String, Object>> comms = new ArrayList<>();
        for (Snmp.Community c : snmp.communities) {
            Map<String, Object> cm = new LinkedHashMap<>();
            cm.put("name", c.name);
            cm.put("classification", c.classification);
            cm.put("evidence", new ArrayList<>(c.evidence));
            comms.add(cm);
        }
        snmpMap.put("communities", comms);
        m.put("snmp", snmpMap);

        Map<String, Object> log = new LinkedHashMap<>();
        log.put("enabled", logging.enabled);
        log.put("hosts", new ArrayList<>(logging.hosts));
        log.put("evidence", new ArrayList<>(logging.evidence));
        m.put("logging", log);
        m.put("evidence_lines", new ArrayList<>(evidenceLines));
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
