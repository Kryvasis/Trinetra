import java.nio.file.*;

/** Regression corpus for hardened, insecure, and incomplete multi-vendor excerpts. */
public class MultiVendorSemanticFixtureTest {
    private static int failures = 0;

    private static void expect(String fixture, String vendor, String control,
                               TrinetraStat.Verdict expected) throws Exception {
        String raw = Files.readString(Path.of("demo", "security-test-pack", fixture));
        SecurityBaseline baseline;
        if ("Cisco".equals(vendor)) baseline = CiscoBaselineAdapter.parse(raw, vendor);
        else if ("Juniper".equals(vendor)) baseline = JuniperBaselineAdapter.parse(raw, vendor);
        else baseline = FortiGateBaselineAdapter.parse(raw, vendor);
        TrinetraStat.Verdict actual = SemanticControlEvaluator.evaluate(control, baseline, raw).verdict;
        if (actual != expected) {
            failures++;
            System.err.println("FAIL " + fixture + " " + control + ": expected " + expected + ", got " + actual);
        }
    }

    public static void main(String[] args) throws Exception {
        expect("cisco-hardened-excerpt.txt", "Cisco", "V-006", TrinetraStat.Verdict.PASS);
        expect("cisco-hardened-excerpt.txt", "Cisco", "V-071", TrinetraStat.Verdict.PASS);
        expect("cisco-insecure.txt", "Cisco", "V-006", TrinetraStat.Verdict.FAIL);
        expect("cisco-insecure.txt", "Cisco", "V-057", TrinetraStat.Verdict.FAIL);
        expect("cisco-incomplete.txt", "Cisco", "V-058", TrinetraStat.Verdict.MANUAL_REVIEW);
        expect("cisco-ambiguous-last-wins.txt", "Cisco", "V-006", TrinetraStat.Verdict.PASS);
        expect("cisco-ambiguous-last-wins.txt", "Cisco", "V-104", TrinetraStat.Verdict.PASS);

        expect("juniper-hardened-excerpt.txt", "Juniper", "V-003", TrinetraStat.Verdict.PASS);
        expect("juniper-hardened-excerpt.txt", "Juniper", "V-071", TrinetraStat.Verdict.PASS);
        expect("juniper-insecure.txt", "Juniper", "V-006", TrinetraStat.Verdict.FAIL);
        expect("juniper-insecure.txt", "Juniper", "V-057", TrinetraStat.Verdict.FAIL);
        expect("juniper-incomplete.txt", "Juniper", "V-058", TrinetraStat.Verdict.MANUAL_REVIEW);
        expect("juniper-ambiguous-last-wins.txt", "Juniper", "V-003", TrinetraStat.Verdict.PASS);
        expect("juniper-ambiguous-last-wins.txt", "Juniper", "V-006", TrinetraStat.Verdict.PASS);

        expect("fortios-hardened-excerpt.txt", "FortiOS", "V-003", TrinetraStat.Verdict.PASS);
        expect("fortios-hardened-excerpt.txt", "FortiOS", "V-071", TrinetraStat.Verdict.PASS);
        expect("fortios-insecure.txt", "FortiOS", "V-003", TrinetraStat.Verdict.FAIL);
        expect("fortios-insecure.txt", "FortiOS", "V-057", TrinetraStat.Verdict.FAIL);
        expect("fortios-incomplete.txt", "FortiOS", "V-058", TrinetraStat.Verdict.MANUAL_REVIEW);
        expect("fortios-ambiguous-last-wins.txt", "FortiOS", "V-003", TrinetraStat.Verdict.PASS);
        expect("fortios-ambiguous-last-wins.txt", "FortiOS", "V-071", TrinetraStat.Verdict.PASS);

        if (failures > 0) throw new AssertionError(failures + " fixture assertion(s) failed");
        System.out.println("MultiVendorSemanticFixtureTest passed (21 assertions across 3 vendors)");
    }
}
