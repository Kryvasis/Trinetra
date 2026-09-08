import java.util.*;

/**
 * Semantic evaluator — maps SecurityBaseline facts to V-code verdicts.
 * Replaces probe-output grep logic for config_upload path.
 * Each method is vendor-neutral; facts are already normalized.
 */
public class SemanticControlEvaluator {

    public static class Result {
        public final TrinetraStat.Verdict verdict;
        public final String detail;
        public final List<String> evidence;
        public Result(TrinetraStat.Verdict verdict, String detail, List<String> evidence) {
            this.verdict = verdict;
            this.detail = detail;
            this.evidence = evidence != null ? new ArrayList<>(evidence) : new ArrayList<>();
        }
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
            case "V-107": return evalV107(baseline);
            // Category 2 — inherently live
            case "V-005":
            case "V-007":
            case "V-008":
            case "V-070":
            case "V-087":
            case "V-105":
            case "V-106":
            case "V-144":
                return new Result(TrinetraStat.Verdict.MANUAL_REVIEW,
                    "Requires live network verification — not determinable from static config alone (Category 2, unsupported check).",
                    List.of());
            default:
                return new Result(TrinetraStat.Verdict.MANUAL_REVIEW, "No semantic rule for " + vc, List.of());
        }
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
            // Has SNMP but not default => pass (assuming at least one custom)
            List<String> allEv = new ArrayList<>();
            for (SecurityBaseline.Snmp.Community c : b.snmp.communities) allEv.addAll(c.evidence);
            return new Result(TrinetraStat.Verdict.PASS,
                "Config-syntax check: secure directive present for V-057 (no default community).",
                dedup(allEv));
        }
        // No SNMP at all => pass (no hardcoded secret)
        if (b.snmp.communities.isEmpty() && !b.evidenceLines.isEmpty()) {
            return new Result(TrinetraStat.Verdict.PASS,
                "Config-syntax check: secure directive present for V-057 (no SNMP default community found).",
                List.of());
        }
        return new Result(TrinetraStat.Verdict.MANUAL_REVIEW,
            "Config check ran but the config contained neither the insecure nor the secure directive for V-057 — insufficient evidence.",
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
        // Heuristic: if config is non-blank but no logging evidence at all => FAIL
        if (b.evidenceLines.isEmpty() && b.logging.hosts.isEmpty() && b.logging.evidence.isEmpty()) {
            return new Result(TrinetraStat.Verdict.FAIL,
                "Config-syntax check: insecure directive present for V-058 (no logging host).",
                List.of());
        }
        if (b.logging.hosts.isEmpty() && b.logging.evidence.isEmpty()) {
            return new Result(TrinetraStat.Verdict.FAIL,
                "Config-syntax check: insecure directive present for V-058 (no logging host).",
                List.of());
        }
        return new Result(TrinetraStat.Verdict.MANUAL_REVIEW,
            "Config check ran but the config contained neither the insecure nor the secure directive for V-058 — insufficient evidence.",
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
        // Also consider SSH version 2 as admin hardening
        if ("2".equals(b.managementPlane.sshVersion)) passEv.addAll(b.managementPlane.sshEvidence);
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
