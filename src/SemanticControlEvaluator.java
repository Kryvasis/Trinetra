import java.util.*;

/**
 * Semantic evaluator — maps SecurityBaseline facts to V-code verdicts.
 * Replaces probe-output grep logic for config_upload path.
 * Each method is vendor-neutral; facts are already normalized.
 */
public class SemanticControlEvaluator {

    public static final String EXPLICIT_SECURE_DIRECTIVE = "explicit_secure_directive";
    public static final String EXPLICIT_INSECURE_DIRECTIVE = "explicit_insecure_directive";
    public static final String INSUFFICIENT_SYNTAX = "insufficient_configuration_evidence";
    public static final String REQUIRES_LIVE_EVIDENCE = "requires_live_evidence";
    public static final String UNSUPPORTED_ASSESSMENT_TYPE = "unsupported_assessment_type";

    private static final Set<String> SEMANTIC_CONTROLS = Set.of(
        "V-003", "V-006", "V-013", "V-057", "V-058", "V-071", "V-104", "V-107", "V-108"
    );
    private static final Set<String> LIVE_REQUIRED_CONTROLS = Set.of(
        "V-004", "V-005", "V-007", "V-008", "V-070", "V-087", "V-105",
        "V-106", "V-110", "V-118", "V-144", "V-145"
    );
    private static final Set<String> OTHER_ASSESSMENT_CONTROLS = Set.of(
        "V-010", "V-056", "V-059", "V-073", "V-074", "V-088", "V-113"
    );

    public static class Result {
        public final TrinetraStat.Verdict verdict;
        public final String detail;
        public final List<String> evidence;
        public final String reasonCode;
        public final String evaluationSource;
        public Result(TrinetraStat.Verdict verdict, String detail, List<String> evidence) {
            this(verdict, detail, evidence,
                verdict == TrinetraStat.Verdict.PASS ? EXPLICIT_SECURE_DIRECTIVE
                    : verdict == TrinetraStat.Verdict.FAIL ? EXPLICIT_INSECURE_DIRECTIVE
                    : INSUFFICIENT_SYNTAX,
                "normalized_configuration");
        }
        public Result(TrinetraStat.Verdict verdict, String detail, List<String> evidence,
                      String reasonCode, String evaluationSource) {
            this.verdict = verdict;
            this.detail = detail;
            this.evidence = evidence != null ? new ArrayList<>(evidence) : new ArrayList<>();
            this.reasonCode = reasonCode;
            this.evaluationSource = evaluationSource;
        }
    }

    public static String configurationMode(String vcode) {
        String vc = vcode == null ? "" : vcode.toUpperCase(Locale.ROOT);
        if (SEMANTIC_CONTROLS.contains(vc)) return "semantic_configuration";
        if (LIVE_REQUIRED_CONTROLS.contains(vc)) return "live_evidence_required";
        if (OTHER_ASSESSMENT_CONTROLS.contains(vc)) return "different_assessment_type_required";
        return "unmapped";
    }

    public static boolean isSemanticControl(String vcode) {
        return vcode != null && SEMANTIC_CONTROLS.contains(vcode.toUpperCase(Locale.ROOT));
    }

    public static Result evaluate(String vcode, SecurityBaseline baseline, String rawConfig) {
        if (vcode == null || baseline == null) return new Result(TrinetraStat.Verdict.MANUAL_REVIEW, "No baseline", List.of());
        String vc = vcode.toUpperCase(Locale.ROOT);
        switch (vc) {
            case "V-003": return evalV003(baseline);
            case "V-006": return evalV006(baseline);
            case "V-013": return evalV013(baseline);
            case "V-057": return evalV057(baseline);
            case "V-058": return evalV058(baseline);
            case "V-071": return evalV071(baseline);
            case "V-104": return evalV104(baseline);
            case "V-107": return evalV107(baseline);
            case "V-108": return evalV108(baseline);
            default:
                if (LIVE_REQUIRED_CONTROLS.contains(vc)) {
                return new Result(TrinetraStat.Verdict.MANUAL_REVIEW,
                    "Static configuration cannot establish a pass; live verification, inventory, scanner, or external-service evidence is required.",
                    List.of(), REQUIRES_LIVE_EVIDENCE, "configuration_scope_gate");
                }
                if (OTHER_ASSESSMENT_CONTROLS.contains(vc)) {
                    return new Result(TrinetraStat.Verdict.MANUAL_REVIEW,
                        "This control targets web applications, host filesystems, software inventories, storage, or CI/CD evidence rather than a network-device configuration.",
                        List.of(), UNSUPPORTED_ASSESSMENT_TYPE, "configuration_scope_gate");
                }
                return new Result(TrinetraStat.Verdict.MANUAL_REVIEW,
                    "No configuration evaluator is registered for " + vc + ".",
                    List.of(), UNSUPPORTED_ASSESSMENT_TYPE, "configuration_scope_gate");
        }
    }

    private static Result evalV104(SecurityBaseline b) {
        if (Boolean.TRUE.equals(b.networkSegmentation.dynamicTrunkingEnabled)) {
            return new Result(TrinetraStat.Verdict.FAIL,
                "Dynamic trunk negotiation is explicitly enabled, increasing VLAN-hopping exposure.",
                dedup(b.networkSegmentation.evidence));
        }
        if (Boolean.FALSE.equals(b.networkSegmentation.dynamicTrunkingEnabled)) {
            return new Result(TrinetraStat.Verdict.PASS,
                "The configuration explicitly disables trunk negotiation or fixes the port in access mode.",
                dedup(b.networkSegmentation.evidence));
        }
        return new Result(TrinetraStat.Verdict.MANUAL_REVIEW,
            "No supported access-port or trunk-negotiation directive was found for V-104.", List.of());
    }

    private static Result evalV108(SecurityBaseline b) {
        if (!"AWS".equalsIgnoreCase(b.vendor)) {
            return new Result(TrinetraStat.Verdict.MANUAL_REVIEW,
                "V-108 applies to cloud firewall/security-group evidence; this device baseline is not an AWS security-group assessment.",
                List.of(), UNSUPPORTED_ASSESSMENT_TYPE, "applicability_gate");
        }
        if (Boolean.TRUE.equals(b.networkSegmentation.publicSensitiveIngress)) {
            return new Result(TrinetraStat.Verdict.FAIL,
                "A security-group rule explicitly exposes a sensitive port to 0.0.0.0/0.",
                dedup(b.networkSegmentation.evidence));
        }
        if (Boolean.FALSE.equals(b.networkSegmentation.publicSensitiveIngress)
                || Boolean.TRUE.equals(b.acl.hasGranularAcls)) {
            return new Result(TrinetraStat.Verdict.PASS,
                "The supplied AWS rules explicitly restrict ingress rather than exposing sensitive ports globally.",
                dedup(b.networkSegmentation.evidence.isEmpty() ? b.acl.evidence : b.networkSegmentation.evidence));
        }
        return new Result(TrinetraStat.Verdict.MANUAL_REVIEW,
            "The AWS input did not contain enough security-group ingress evidence to decide V-108.", List.of());
    }

    private static Result evalV003(SecurityBaseline b) {
        // Unnecessary services: http, telnet, source-route
        List<String> failEvidence = new ArrayList<>();
        if (Boolean.TRUE.equals(b.managementPlane.httpEnabled)) failEvidence.addAll(b.managementPlane.httpEvidence);
        if (Boolean.TRUE.equals(b.managementPlane.telnetEnabled)) failEvidence.addAll(b.managementPlane.telnetEvidence);
        if (Boolean.TRUE.equals(b.managementPlane.sourceRouteEnabled)) failEvidence.addAll(b.managementPlane.sourceRouteEvidence);
        if (!failEvidence.isEmpty()) {
            return new Result(TrinetraStat.Verdict.FAIL,
                "Config-syntax check: insecure directive present for V-003 (unnecessary service).",
                dedup(failEvidence));
        }
        List<String> passEvidence = new ArrayList<>();
        if (Boolean.FALSE.equals(b.managementPlane.httpEnabled)) passEvidence.addAll(b.managementPlane.httpEvidence);
        if (Boolean.FALSE.equals(b.managementPlane.sourceRouteEnabled)) passEvidence.addAll(b.managementPlane.sourceRouteEvidence);
        if (Boolean.FALSE.equals(b.managementPlane.telnetEnabled)) passEvidence.addAll(b.managementPlane.telnetEvidence);
        if (!passEvidence.isEmpty()) {
            return new Result(TrinetraStat.Verdict.PASS,
                "Config-syntax check: secure directive present for V-003 (unnecessary services disabled).",
                dedup(passEvidence));
        }
        return new Result(TrinetraStat.Verdict.MANUAL_REVIEW,
            "Config check ran but the config contained neither the insecure nor the secure directive for V-003 — insufficient evidence.",
            List.of());
    }

    private static Result evalV006(SecurityBaseline b) {
        if ("1".equals(b.managementPlane.sshVersion)) {
            return new Result(TrinetraStat.Verdict.FAIL,
                "Config-syntax check: insecure directive present for V-006 (ssh version 1).",
                dedup(b.managementPlane.sshEvidence));
        }
        if ("2".equals(b.managementPlane.sshVersion)) {
            return new Result(TrinetraStat.Verdict.PASS,
                "Config-syntax check: secure directive present for V-006 (ssh version 2).",
                dedup(b.managementPlane.sshEvidence));
        }
        return new Result(TrinetraStat.Verdict.MANUAL_REVIEW,
            "Config check ran but the config contained neither the insecure nor the secure directive for V-006 — insufficient evidence.",
            List.of());
    }

    private static Result evalV013(SecurityBaseline b) {
        List<String> failEv = new ArrayList<>();
        if (Boolean.TRUE.equals(b.authentication.hasEnablePassword)) failEv.addAll(b.authentication.enablePasswordEvidence);
        for (SecurityBaseline.Authentication.User u : b.authentication.users) {
            if ("password".equals(u.authType) || "plain-text-password".equals(u.authType)) failEv.addAll(u.evidence);
        }
        if (!failEv.isEmpty()) {
            return new Result(TrinetraStat.Verdict.FAIL,
                "Config-syntax check: insecure directive present for V-013 (weak password).",
                dedup(failEv));
        }
        List<String> passEv = new ArrayList<>();
        if (Boolean.TRUE.equals(b.authentication.hasEnableSecret)) passEv.addAll(b.authentication.enableSecretEvidence);
        if (Boolean.TRUE.equals(b.authentication.aaaEnabled)) passEv.addAll(b.authentication.aaaEvidence);
        if (Boolean.TRUE.equals(b.authentication.passwordEncryptionEnabled)) passEv.addAll(b.authentication.passwordEncryptionEvidence);
        for (SecurityBaseline.Authentication.User u : b.authentication.users) {
            if ("secret".equals(u.authType) || "encrypted-password".equals(u.authType)) passEv.addAll(u.evidence);
        }
        if (!passEv.isEmpty()) {
            return new Result(TrinetraStat.Verdict.PASS,
                "Config-syntax check: secure directive present for V-013 (strong auth).",
                dedup(passEv));
        }
        return new Result(TrinetraStat.Verdict.MANUAL_REVIEW,
            "Config check ran but the config contained neither the insecure nor the secure directive for V-013 — insufficient evidence.",
            List.of());
    }

    private static Result evalV057(SecurityBaseline b) {
        List<String> failEv = new ArrayList<>();
        for (SecurityBaseline.Snmp.Community c : b.snmp.communities) {
            if ("default-public".equals(c.classification) || "default-private".equals(c.classification)) {
                failEv.addAll(c.evidence);
            }
        }
        if (!failEv.isEmpty()) {
            return new Result(TrinetraStat.Verdict.FAIL,
                "Config-syntax check: insecure directive present for V-057 (default SNMP community).",
                dedup(failEv));
        }
        if (!b.snmp.communities.isEmpty()) {
            // SNMPv1/v2c community strings are shared secrets even when their
            // values are not the defaults. Their presence is direct evidence
            // for this hardcoded-secret control, but values stay redacted by
            // the evidence sanitizer.
            List<String> allEv = new ArrayList<>();
            for (SecurityBaseline.Snmp.Community c : b.snmp.communities) allEv.addAll(c.evidence);
            return new Result(TrinetraStat.Verdict.FAIL,
                "Config-syntax check: an SNMP community string is embedded in the supplied configuration.",
                dedup(allEv));
        }
        return new Result(TrinetraStat.Verdict.MANUAL_REVIEW,
            "No SNMP community was observed, but absence from a partial export cannot prove that no hardcoded secret exists.",
            List.of());
    }

    private static Result evalV058(SecurityBaseline b) {
        if (Boolean.TRUE.equals(b.logging.enabled) && !b.logging.hosts.isEmpty()) {
            return new Result(TrinetraStat.Verdict.PASS,
                "Config-syntax check: secure directive present for V-058 (logging host).",
                dedup(b.logging.evidence));
        }
        if (Boolean.TRUE.equals(b.logging.enabled)) {
            return new Result(TrinetraStat.Verdict.PASS,
                "Config-syntax check: secure directive present for V-058 (logging enabled).",
                dedup(b.logging.evidence));
        }
        if (Boolean.FALSE.equals(b.logging.enabled)) {
            return new Result(TrinetraStat.Verdict.FAIL,
                "Config-syntax check: insecure directive present for V-058 (logging disabled).",
                dedup(b.logging.evidence));
        }
        return new Result(TrinetraStat.Verdict.MANUAL_REVIEW,
            "No explicit logging state was found; absence from a partial export cannot prove a logging failure.",
            List.of());
    }

    private static Result evalV071(SecurityBaseline b) {
        List<String> failEv = new ArrayList<>();
        if (Boolean.TRUE.equals(b.managementPlane.telnetEnabled)) failEv.addAll(b.managementPlane.telnetEvidence);
        if (Boolean.TRUE.equals(b.managementPlane.httpEnabled)) failEv.addAll(b.managementPlane.httpEvidence);
        if ("0 0".equals(b.managementPlane.execTimeout)) failEv.addAll(b.managementPlane.execTimeoutEvidence);
        if ("0".equals(b.managementPlane.execTimeout)) failEv.addAll(b.managementPlane.execTimeoutEvidence);
        if (!failEv.isEmpty()) {
            return new Result(TrinetraStat.Verdict.FAIL,
                "Config-syntax check: insecure directive present for V-071 (exposed admin interface).",
                dedup(failEv));
        }
        List<String> passEv = new ArrayList<>();
        if (Boolean.FALSE.equals(b.managementPlane.telnetEnabled) || (b.managementPlane.telnetEnabled == null && b.managementPlane.sshEvidence.size() > 0)) {
            // SSH present without telnet is a positive signal but tie to explicit telnet disable or transport input ssh
            if (Boolean.FALSE.equals(b.managementPlane.telnetEnabled)) passEv.addAll(b.managementPlane.telnetEvidence);
        }
        if (Boolean.FALSE.equals(b.managementPlane.httpEnabled)) passEv.addAll(b.managementPlane.httpEvidence);
        if (b.managementPlane.execTimeout != null && !"0 0".equals(b.managementPlane.execTimeout) && !"0".equals(b.managementPlane.execTimeout)) {
            passEv.addAll(b.managementPlane.execTimeoutEvidence);
        }
        if (!passEv.isEmpty()) {
            return new Result(TrinetraStat.Verdict.PASS,
                "Config-syntax check: secure directive present for V-071 (admin interface hardened).",
                dedup(passEv));
        }
        return new Result(TrinetraStat.Verdict.MANUAL_REVIEW,
            "Config check ran but the config contained neither the insecure nor the secure directive for V-071 — insufficient evidence.",
            List.of());
    }

    private static Result evalV107(SecurityBaseline b) {
        List<String> failEv = new ArrayList<>();
        for (SecurityBaseline.Authentication.User u : b.authentication.users) {
            if ("password".equals(u.authType) || "plain-text-password".equals(u.authType)) failEv.addAll(u.evidence);
        }
        if (!failEv.isEmpty()) {
            return new Result(TrinetraStat.Verdict.FAIL,
                "Config-syntax check: insecure directive present for V-107 (IAM weak).",
                dedup(failEv));
        }
        List<String> passEv = new ArrayList<>();
        for (SecurityBaseline.Authentication.User u : b.authentication.users) {
            if ("secret".equals(u.authType) || "encrypted-password".equals(u.authType)) passEv.addAll(u.evidence);
        }
        if (Boolean.TRUE.equals(b.authentication.aaaEnabled)) passEv.addAll(b.authentication.aaaEvidence);
        if (!passEv.isEmpty()) {
            return new Result(TrinetraStat.Verdict.PASS,
                "Config-syntax check: secure directive present for V-107 (IAM hardened).",
                dedup(passEv));
        }
        return new Result(TrinetraStat.Verdict.MANUAL_REVIEW,
            "Config check ran but the config contained neither the insecure nor the secure directive for V-107 — insufficient evidence.",
            List.of());
    }

    private static List<String> dedup(List<String> in) {
        LinkedHashSet<String> s = new LinkedHashSet<>(in);
        List<String> out = new ArrayList<>(s);
        if (out.size() > 10) return out.subList(0, 10);
        return out;
    }
}
