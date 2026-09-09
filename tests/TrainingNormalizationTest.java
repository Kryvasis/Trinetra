import java.util.List;

/** Regression coverage for governed, normalization-aware runtime rules. */
public class TrainingNormalizationTest {
    public static void main(String[] args) {
        VendorTrainingMap.Entry sshRule = new VendorTrainingMap.Entry(
            "Cisco", "^custom ssh-version (\\d+)$", "Cryptography", List.of("CIS-v8-3.10"),
            "Use SSH version 2.", "2026-09-09T00:00:00Z", "IOS XE 17.6",
            "V-006", "management_plane.ssh_version", "$1",
            "^no custom ssh-version$", "", "^line vty.*", "IOS XE 17\\..*", 20,
            List.of("custom ssh-version 2"), List.of("logging host 10.0.0.1")
        );
        if (!sshRule.appliesTo("Cisco", "IOS XE 17.6.5", "line vty 0 4"))
            throw new AssertionError("version/context applicability failed");
        if (sshRule.appliesTo("Cisco", "IOS XE 16.12", "line vty 0 4"))
            throw new AssertionError("OS version gate failed");
        if (!sshRule.matches("custom ssh-version 2"))
            throw new AssertionError("positive pattern failed");
        if (!"2".equals(sshRule.resolvedValue("custom ssh-version 2")))
            throw new AssertionError("capture-group transformation failed");

        SecurityBaseline baseline = new SecurityBaseline();
        if (!baseline.applyTrainingValue(sshRule.baselineField,
                sshRule.resolvedValue("custom ssh-version 2"), "trained test"))
            throw new AssertionError("allow-listed baseline mutation failed");
        if (!"2".equals(baseline.managementPlane.sshVersion))
            throw new AssertionError("baseline value was not stored");
        if (baseline.applyTrainingValue("java.class.path", "x", "unsafe"))
            throw new AssertionError("unknown baseline field was accepted");

        baseline.applyTrainingValue("network_segmentation.dynamic_trunking_enabled", "true", "dynamic");
        SemanticControlEvaluator.Result vlan = SemanticControlEvaluator.evaluate("V-104", baseline, "");
        if (vlan.verdict != TrinetraStat.Verdict.FAIL)
            throw new AssertionError("trained segmentation fact was not evaluated");
        if (!SemanticControlEvaluator.REQUIRES_LIVE_EVIDENCE.equals(
                SemanticControlEvaluator.evaluate("V-070", baseline, "").reasonCode))
            throw new AssertionError("live-evidence reason was not explicit");
        if (!SemanticControlEvaluator.UNSUPPORTED_ASSESSMENT_TYPE.equals(
                SemanticControlEvaluator.evaluate("V-088", baseline, "").reasonCode))
            throw new AssertionError("assessment-type reason was not explicit");
        System.out.println("TrainingNormalizationTest passed");
    }
}
