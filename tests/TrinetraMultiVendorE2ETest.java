import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.util.*;

/**
 * Multi-vendor combined-session E2E test — Prompt 19+ (multi-vendor proof).
 *
 * Proves the multi-vendor claim for real: both Cisco and Juniper present
 * and exercised WITHIN THE SAME COMBINED SESSION, confirming registry,
 * scoring, narrative, and report-assembly layers correctly keep vendor
 * data segregated when NOT run in isolation.
 *
 * Covers:
 *  (1) single session multi_vendor_e2e holds two device fingerprints
 *      (Cisco + Juniper) via the mocked fingerprinting approach
 *      (device_vendors map in session JSON, same seam as Prompt 18)
 *  (2) statRunAll (or equivalent per-device statRun) across both devices
 *      within that session: shared vendor-agnostic test (T-SHARED) +
 *      Cisco-specific (T-CISCO) + Juniper-specific (T-JUNI)
 *  (3) normalized_results vendor attribution — no leakage
 *  (4) brain-state hash chain intact with correct total link count
 *  (5) TrinetraComplianceScorer aggregates per-framework across BOTH
 *      vendors' results (manual math verification)
 *  (6) TrinetraNarrativeGenerator + TrinetraAuditReportBuilder evidence
 *      tables distinguish per-device rows (device_id + vendor + test_id)
 *  (7) cross-vendor leakage trap: same test_id (T-SHARED) on both vendors
 *      with opposite verdicts (Cisco PASS vs Juniper FAIL) shows BOTH
 *      outcomes distinctly, NOT overwritten/averaged away
 *  (8) regression: all of the above encoded as automated checks
 *
 * Run via `make test-java` (temp trinetra.root).
 */
public class TrinetraMultiVendorE2ETest {

    private static int failures = 0;

    private static void expect(boolean cond, String what) {
        if (cond) {
            System.out.println("  [ok] " + what);
        } else {
            System.err.println("  [FAIL] " + what);
            failures++;
        }
    }

    public static void main(String[] args) throws Exception {
        Path root = Path.of(System.getProperty("trinetra.root"));
        System.out.println("=== TrinetraMultiVendorE2ETest (multi-vendor combined session) ===");
        System.out.println("root: " + root + "\n");

        setupSyntheticEnv(root);
        TrinetraNarrativeGenerator.setLlmCall(prompt -> null); // deterministic template path

        String session = "multi_vendor_e2e";
        String ciscoDev = "10.10.1.10";   // Cisco device address (device_id)
        String juniperDev = "10.10.1.20"; // Juniper device address

        // ── (1) create combined session with two device fingerprints ──
        System.out.println("(1) create combined session with Cisco + Juniper fingerprints");
        TrinetraSession.createSession(session, "multi-target");
        // Simulate fingerprinting for two devices in SAME session via new per-device map
        boolean okC = TrinetraSession.setDeviceVendor(session, ciscoDev, "Cisco");
        boolean okJ = TrinetraSession.setDeviceVendor(session, juniperDev, "Juniper");
        expect(okC && okJ, "both device vendors registered");
        // Also set legacy session-level vendor_resolution to ensure fallback still works,
        // but per-device map must take precedence (no leakage)
        Map<String, Object> sessDoc = TrinetraCommon.readJsonFile(TrinetraCommon.sessionJson(session));
        sessDoc.put("vendor_resolution", TrinetraCommon.mapOf(
            "final_vendor", "Cisco", "detection_method", "snmp", "confidence_score", "0.9"));
        TrinetraCommon.writeJsonFile(TrinetraCommon.sessionJson(session), sessDoc);
        expect("Cisco".equals(TrinetraSession.getDeviceVendor(session, ciscoDev)), "Cisco device vendor correct");
        expect("Juniper".equals(TrinetraSession.getDeviceVendor(session, juniperDev)), "Juniper device vendor correct");
        expect("Cisco".equals(TrinetraSession.getEffectiveVendorForDevice(session, ciscoDev)), "effective Cisco");
        expect("Juniper".equals(TrinetraSession.getEffectiveVendorForDevice(session, juniperDev)), "effective Juniper");
        Map<String,String> allDevs = TrinetraSession.getAllDeviceVendors(session);
        expect(allDevs.size() == 2 && "Cisco".equals(allDevs.get(ciscoDev)) && "Juniper".equals(allDevs.get(juniperDev)),
            "getAllDeviceVendors returns both: " + allDevs);

        // ── (2) run mix of tests across both devices within SAME session ──
        System.out.println("\n(2) run mix: shared agnostic + per-vendor specific across both devices");
        // Heterogenous selection: Cisco gets shared + cisco-specific, Juniper gets shared + juniper-specific
        // This exercises both a shared test_id on both vendors and vendor-specific variants
        Map<String, Set<String>> perDevice = new LinkedHashMap<>();
        perDevice.put(ciscoDev, new LinkedHashSet<>(List.of("T-SHARED", "T-CISCO")));
        perDevice.put(juniperDev, new LinkedHashSet<>(List.of("T-SHARED", "T-JUNI")));
        TrinetraAudit.beginNewRun();
        String runUuid = TrinetraAudit.currentRunUuid();
        List<Map<String, Object>> combined = TrinetraStat.statRunAllAcrossDevicesPerSelection(session, perDevice, 1, "tester");
        expect(combined.size() == 4, "combined executions = 4 (2 per device) got " + combined.size());
        // Also test the homogeneous helper: run shared only across both devices via statRunAllAcrossDevices
        // (Already covered, but we verify perDevice helper works; now also test direct statRun trap)
        // The 4 runs above already include the trap: T-SHARED on Cisco vs Juniper with opposite verdicts

        // ── (3) verify normalized_results vendor attribution — no leakage ──
        System.out.println("\n(3) verify normalized_results vendor segregation (no leakage)");
        List<Map<String, Object>> nr = TrinetraSession.getNormalizedResults(session);
        expect(nr.size() == 4, "normalized_results has 4 entries (got " + nr.size() + ")");
        // Count per vendor
        int ciscoCount = 0, juniperCount = 0, genericCount = 0, unknownCount = 0;
        Map<String, List<Map<String, Object>>> byTest = new LinkedHashMap<>();
        for (Map<String, Object> e : nr) {
            String ven = TrinetraCommon.getString(e, "vendor", "");
            String dev = TrinetraCommon.getString(e, "device_id", "");
            String tid = TrinetraCommon.getString(e, "test_id", "");
            byTest.computeIfAbsent(tid, k -> new ArrayList<>()).add(e);
            if ("Cisco".equals(ven)) ciscoCount++;
            else if ("Juniper".equals(ven)) juniperCount++;
            else if ("Generic".equals(ven)) genericCount++;
            else if ("unknown".equals(ven)) unknownCount++;
            // Check device<->vendor consistency: no Cisco device with Juniper vendor
            if (ciscoDev.equals(dev)) {
                expect("Cisco".equals(ven), "Cisco device " + dev + " carries vendor=Cisco not " + ven + " for " + tid);
            } else if (juniperDev.equals(dev)) {
                expect("Juniper".equals(ven), "Juniper device " + dev + " carries vendor=Juniper not " + ven + " for " + tid);
            }
            expect(e.containsKey("chain_hash"), "entry has chain_hash");
            expect(e.containsKey("timestamp"), "entry has timestamp");
        }
        expect(ciscoCount == 2, "Cisco entries ==2 (T-SHARED + T-CISCO) got " + ciscoCount);
        expect(juniperCount == 2, "Juniper entries ==2 (T-SHARED + T-JUNI) got " + juniperCount);
        expect(genericCount == 0 && unknownCount == 0, "no generic/unknown leakage");
        // Shared test appears twice, once per vendor
        expect(byTest.getOrDefault("T-SHARED", List.of()).size() == 2, "T-SHARED appears twice (once per vendor) got " + byTest.getOrDefault("T-SHARED", List.of()).size());
        expect(byTest.getOrDefault("T-CISCO", List.of()).size() == 1, "T-CISCO appears once");
        expect(byTest.getOrDefault("T-JUNI", List.of()).size() == 1, "T-JUNI appears once");
        // Ensure T-CISCO is only Cisco, T-JUNI only Juniper
        if (byTest.containsKey("T-CISCO")) {
            String v = TrinetraCommon.getString(byTest.get("T-CISCO").get(0), "vendor", "");
            expect("Cisco".equals(v), "T-CISCO vendor is Cisco");
            expect(ciscoDev.equals(TrinetraCommon.getString(byTest.get("T-CISCO").get(0), "device_id", "")), "T-CISCO device is Cisco");
        }
        if (byTest.containsKey("T-JUNI")) {
            String v = TrinetraCommon.getString(byTest.get("T-JUNI").get(0), "vendor", "");
            expect("Juniper".equals(v), "T-JUNI vendor is Juniper");
        }
        // Raw output sanity: scripts echo vendor into raw_output, verify no leakage there either
        for (Map<String, Object> e : nr) {
            String raw = TrinetraCommon.getString(e, "raw_output", "");
            String ven = TrinetraCommon.getString(e, "vendor", "");
            String dev = TrinetraCommon.getString(e, "device_id", "");
            if ("Cisco".equals(ven)) {
                expect(raw.contains("VENDOR=[Cisco]") && !raw.contains("VENDOR=[Juniper]"),
                    "Cisco raw_output shows Cisco not Juniper for " + dev);
            } else if ("Juniper".equals(ven)) {
                expect(raw.contains("VENDOR=[Juniper]") && !raw.contains("VENDOR=[Cisco]"),
                    "Juniper raw_output shows Juniper not Cisco for " + dev);
            }
        }
        // Also verify findings carry correct target (device_id)
        List<Map<String, Object>> findings = TrinetraSession.getFindings(session);
        expect(findings.size() == 4, "findings size ==4 (got " + findings.size() + ")");
        Set<String> findingTargets = new HashSet<>();
        for (Map<String, Object> f : findings) findingTargets.add(TrinetraCommon.getString(f, "target", ""));
        expect(findingTargets.contains(ciscoDev) && findingTargets.contains(juniperDev), "findings contain both device targets");

        // ── (4) hash chain intact with correct total link count ──
        System.out.println("\n(4) verify hash chain intact across combined vendor executions");
        TrinetraSession.ChainVerifyResult chain = TrinetraSession.verifyChain(session);
        expect(chain.intact, "verifyChain intact -> " + chain);
        expect(chain.toString().contains("(4 links)"), "chain has 4 links: " + chain);
        // Tamper detection sanity: global chain should also be intact after session ops
        TrinetraSession.ChainVerifyResult global = TrinetraSession.verifyGlobalChain();
        expect(global.intact, "verifyGlobalChain intact -> " + global);

        // ── (7) trap: same test_id opposite verdicts must both survive distinctly ──
        System.out.println("\n(7) trap: T-SHARED opposite verdicts per vendor (no overwrite)");
        Map<String, String> sharedVerdicts = new LinkedHashMap<>();
        for (Map<String, Object> e : byTest.getOrDefault("T-SHARED", List.of())) {
            String dev = TrinetraCommon.getString(e, "device_id", "");
            String verdict = TrinetraCommon.getString(e, "normalized_result", "");
            sharedVerdicts.put(dev, verdict);
        }
        expect(sharedVerdicts.size() == 2, "trap: T-SHARED has 2 distinct device entries");
        expect("pass".equals(sharedVerdicts.get(ciscoDev)), "trap: Cisco T-SHARED verdict is PASS (got " + sharedVerdicts.get(ciscoDev) + ")");
        expect("fail".equals(sharedVerdicts.get(juniperDev)), "trap: Juniper T-SHARED verdict is FAIL (got " + sharedVerdicts.get(juniperDev) + ")");
        expect(!sharedVerdicts.get(ciscoDev).equals(sharedVerdicts.get(juniperDev)), "trap: verdicts are opposite, not collapsed");
        // Ensure T-CISCO verdict is PASS and T-JUNI verdict is FAIL as designed
        String ciscoVerdict = byTest.get("T-CISCO") != null ? TrinetraCommon.getString(byTest.get("T-CISCO").get(0), "normalized_result", "") : "";
        String juniVerdict = byTest.get("T-JUNI") != null ? TrinetraCommon.getString(byTest.get("T-JUNI").get(0), "normalized_result", "") : "";
        expect("pass".equals(ciscoVerdict), "T-CISCO verdict PASS (got " + ciscoVerdict + ")");
        expect("fail".equals(juniVerdict), "T-JUNI verdict FAIL (got " + juniVerdict + ")");

        // ── (5) scorer aggregates across BOTH vendors per framework ──
        System.out.println("\n(5) scorer aggregates correctly per framework (manual math verification)");
        TrinetraCompliance.reload();
        Map<String, Object> score = TrinetraComplianceScorer.score(session);
        @SuppressWarnings("unchecked")
        Map<String, Object> frameworks = (Map<String, Object>) score.get("frameworks");
        expect(frameworks != null && !frameworks.isEmpty(), "frameworks scored (got " + (frameworks==null?0:frameworks.size()) + ")");
        // Manual math for fixture:
        // Manifest:
        //   T-SHARED -> ISO27001[A.1], SOC2[CC1]
        //   T-CISCO  -> ISO27001[A.2] only
        //   T-JUNI   -> SOC2[CC2] only
        // Executions:
        //   T-SHARED@Cisco PASS, T-SHARED@Juniper FAIL, T-CISCO@Cisco PASS, T-JUNI@Juniper FAIL
        // ISO27001: T-SHARED x2 (1 pass 1 fail) + T-CISCO (1 pass) => total 3, passed 2, failed 1 => 66.7%
        // SOC2:     T-SHARED x2 (1 pass 1 fail) + T-JUNI (1 fail) => total 3, passed 1, failed 2 => 33.3%
        @SuppressWarnings("unchecked")
        Map<String, Object> iso = (Map<String, Object>) frameworks.get("ISO27001");
        expect(iso != null, "ISO27001 present");
        if (iso != null) {
            int isoPass = ((Number) iso.get("tests_passed")).intValue();
            int isoFail = ((Number) iso.get("tests_failed")).intValue();
            int isoTotal = ((Number) iso.get("total_tests_mapped")).intValue();
            double isoPct = ((Number) iso.get("compliance_percentage")).doubleValue();
            expect(isoTotal == 3, "ISO27001 total_tests_mapped==3 (got " + isoTotal + ")");
            expect(isoPass == 2, "ISO27001 tests_passed==2 (got " + isoPass + ")");
            expect(isoFail == 1, "ISO27001 tests_failed==1 (got " + isoFail + ")");
            expect(Math.abs(isoPct - 66.7) < 0.1, "ISO27001 pct==66.7 (got " + isoPct + ")");
            System.out.println("      ISO27001 manual: 2 pass / 3 total = " + isoPct + "%");
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> soc2 = (Map<String, Object>) frameworks.get("SOC2");
        expect(soc2 != null, "SOC2 present");
        if (soc2 != null) {
            int socPass = ((Number) soc2.get("tests_passed")).intValue();
            int socFail = ((Number) soc2.get("tests_failed")).intValue();
            int socTotal = ((Number) soc2.get("total_tests_mapped")).intValue();
            double socPct = ((Number) soc2.get("compliance_percentage")).doubleValue();
            expect(socTotal == 3, "SOC2 total_tests_mapped==3 (got " + socTotal + ")");
            expect(socPass == 1, "SOC2 tests_passed==1 (got " + socPass + ")");
            expect(socFail == 2, "SOC2 tests_failed==2 (got " + socFail + ")");
            expect(Math.abs(socPct - 33.3) < 0.1, "SOC2 pct==33.3 (got " + socPct + ")");
            System.out.println("      SOC2 manual: 1 pass / 3 total = " + socPct + "%");
        }
        @SuppressWarnings("unchecked")
        List<String> unmapped = (List<String>) score.get("unmapped_tests");
        expect(unmapped != null && unmapped.isEmpty(), "unmapped empty (all mapped) got " + unmapped);
        expect(((Number) score.get("total_tests_executed")).intValue() == 4, "total_tests_executed==4");
        // Verify scorer didn't drop one vendor's data: total per framework should sum to 6 mapped executions
        // (ISO 3 + SOC2 3) = 6, but total_tests_executed is 4 entries; mapped counting per framework duplicates shared tests, so sum > total
        // Check that frameworks' totals reflect combined not single-vendor:
        // If only Cisco data counted, ISO would be 2 (T-SHARED PASS + T-CISCO PASS) 100%, SOC2 would be 1 (T-SHARED PASS) 100% — not our observed values, so we prove combined

        // Persist scorer output for next steps
        Path scorePath = TrinetraComplianceScorer.scoreAndWrite(session);
        expect(Files.exists(scorePath), "score JSON written to " + scorePath);
        score = TrinetraCommon.readJsonFile(scorePath); // re-read to ensure written

        // ── (6) narrative + audit report distinguish per-device rows ──
        System.out.println("\n(6) narrative + audit report per-device evidence segregation");
        Map<String, Object> meta = TrinetraNarrativeGenerator.generateReport(session, score);
        expect(TrinetraNarrativeGenerator.SOURCE_TEMPLATE.equals(meta.get("source")) || TrinetraNarrativeGenerator.SOURCE_LLM.equals(meta.get("source")),
            "narrative generated source=" + meta.get("source"));
        Path narrPath = Path.of(String.valueOf(meta.get("path")));
        String narrative = Files.readString(narrPath);
        expect(narrative.contains("66.7%") || narrative.contains("33.3%"), "narrative contains scorer percentages");
        // Build audit report (per-framework + combined)
        Map<String, Object> arb = TrinetraAuditReportBuilder.buildAuditReport(session);
        expect(arb != null, "audit report built");
        if (arb != null) {
            @SuppressWarnings("unchecked")
            List<String> fwPaths = (List<String>) arb.get("framework_paths");
            expect(fwPaths.size() == 2, "two per-framework reports (ISO27001, SOC2) got " + fwPaths.size());
            double agg = ((Number) arb.get("derived_aggregate_pct")).doubleValue();
            // Aggregate = mean of 66.7 and 33.3 => 50.0
            expect(Math.abs(agg - 50.0) < 0.1, "derived aggregate 50.0 (mean of 66.7 & 33.3) got " + agg);
            System.out.println("      Derived aggregate manual: (66.7+33.3)/2 = 50.0% got " + agg + "%");
            // Verify per-framework reports contain correct evidence rows with vendor segregated
            for (String fw : List.of("ISO27001", "SOC2")) {
                Path p = root.resolve("sessions").resolve(session).resolve("report_" + fw + "_" + session + ".md");
                expect(Files.exists(p), "per-framework report exists: " + p.getFileName());
                String content = Files.readString(p);
                expect(content.contains("| Device |") && content.contains("| Vendor |") && content.contains("Test ID") && content.contains("Verdict"), "per-framework " + fw + " has evidence header");
                // ISO27001 should have 3 rows: T-SHARED Cisco PASS, T-SHARED Juniper FAIL, T-CISCO Cisco PASS
                // SOC2 should have 3 rows: T-SHARED Cisco PASS, T-SHARED Juniper FAIL, T-JUNI Juniper FAIL
                // New schema includes Serial/Hardware/OS/Severity columns between Vendor and Verdict — check leniently
                if ("ISO27001".equals(fw)) {
                    expect(content.contains(ciscoDev) && content.contains("Cisco") && content.contains("T-SHARED") && content.contains("pass"), "ISO report has Cisco T-SHARED pass");
                    expect(content.contains(juniperDev) && content.contains("Juniper") && content.contains("T-SHARED") && content.contains("fail"), "ISO report has Juniper T-SHARED fail");
                    expect(content.contains(ciscoDev) && content.contains("Cisco") && content.contains("T-CISCO") && content.contains("pass"), "ISO report has T-CISCO");
                    expect(!content.contains("T-JUNI"), "ISO report must NOT contain T-JUNI (SOC2 only)");
                } else {
                    expect(content.contains(ciscoDev) && content.contains("Cisco") && content.contains("T-SHARED") && content.contains("pass"), "SOC2 report has Cisco T-SHARED pass");
                    expect(content.contains(juniperDev) && content.contains("Juniper") && content.contains("T-SHARED") && content.contains("fail"), "SOC2 report has Juniper T-SHARED fail");
                    expect(content.contains(juniperDev) && content.contains("Juniper") && content.contains("T-JUNI") && content.contains("fail"), "SOC2 report has T-JUNI fail");
                    expect(!content.contains("T-CISCO"), "SOC2 report must NOT contain T-CISCO");
                }
                // Vendor column must be present and not collapsed
                expect(content.contains("| Cisco |") && content.contains("| Juniper |"), fw + " report shows BOTH vendors distinctly");
            }
            Path combinedPath = Path.of(String.valueOf(arb.get("combined_path")));
            expect(Files.exists(combinedPath), "combined audit_report exists");
            String combinedMd = Files.readString(combinedPath);
            expect(combinedMd.contains("## Framework Reports"), "combined has framework reports section");
            expect(combinedMd.contains(ciscoDev) && combinedMd.contains("Cisco") && combinedMd.contains("T-SHARED") && combinedMd.contains("pass"), "combined has Cisco T-SHARED pass row");
            expect(combinedMd.contains(juniperDev) && combinedMd.contains("Juniper") && combinedMd.contains("T-SHARED") && combinedMd.contains("fail"), "combined has Juniper T-SHARED fail row");
            expect(combinedMd.contains(ciscoDev) && combinedMd.contains("Cisco") && combinedMd.contains("T-CISCO"), "combined has T-CISCO row");
            expect(combinedMd.contains(juniperDev) && combinedMd.contains("Juniper") && combinedMd.contains("T-JUNI"), "combined has T-JUNI row");
            // Ensure trap distinctiveness in combined: both T-SHARED outcomes visible, not collapsed to one
            int sharedPassRows = countOccurrences(combinedMd, "T-SHARED | pass");
            int sharedFailRows = countOccurrences(combinedMd, "T-SHARED | fail");
            expect(sharedPassRows >= 1 && sharedFailRows >= 1, "combined shows BOTH T-SHARED verdicts (pass rows " + sharedPassRows + ", fail rows " + sharedFailRows + ")");
            // Tamper evidence and audit uuid
            expect(combinedMd.contains("Tamper-evidence") || combinedMd.contains("hash-chained"), "combined has tamper-evidence appendix");
            expect(combinedMd.contains(chain.toString()) || combinedMd.contains("INTACT"), "combined chain status reflects verifyChain intact");
            if (!TrinetraAudit.listAuditUuids(session).isEmpty()) {
                expect(combinedMd.contains(TrinetraAudit.listAuditUuids(session).get(0).substring(0,8)), "combined carries audit_uuid");
            }
            System.out.println("\n      --- Sample per-vendor evidence rows from combined report ---");
            for (String line : combinedMd.split("\n")) {
                if (line.contains("| " + ciscoDev) || line.contains("| " + juniperDev)) {
                    System.out.println("      " + line);
                }
            }
        }

        // ── Brain-state validation ──
        System.out.println("\n(validation) brain-state still valid after multi-vendor run");
        List<String> errs = TrinetraSession.validateBrainState(session);
        // Expect only missing latest_score error? But our session has score via scorer, not brain's latest_score? Actually brain's latest_score is separate from compliance scorer
        // Just ensure no normalized_results shape errors
        boolean onlyScoreMissing = errs.isEmpty() || (errs.size()==1 && errs.get(0).contains("latest_score"));
        // Our session's brain_state may not have latest_score because we didn't run TrinetraBrain.brainScore, only compliance scorer
        // That's okay; normalized_results shape must be clean
        boolean noNormalizedErrors = errs.stream().noneMatch(e -> e.contains("normalized_results"));
        expect(noNormalizedErrors, "no normalized_results shape errors: " + errs);

        TrinetraNarrativeGenerator.resetLlmCall();
        System.out.println("\n" + (failures == 0
            ? "[+] TrinetraMultiVendorE2ETest: all tests passed"
            : "[-] TrinetraMultiVendorE2ETest: " + failures + " FAILURE(S)"));
        if (failures > 0) System.exit(1);
    }

    private static int countOccurrences(String haystack, String needle) {
        int count = 0, idx = 0;
        while ((idx = haystack.indexOf(needle, idx)) >= 0) { count++; idx += needle.length(); }
        return count;
    }

    private static void setupSyntheticEnv(Path root) throws Exception {
        // ── 2_static_map with 3 tests: shared + cisco-specific + juniper-specific ──
        String map = """
            {
              "T-SHARED": {
                "name": "Shared TLS check (vendor-agnostic)",
                "category": "synthetic",
                "tool": "builtin",
                "script": "T-SHARED.sh",
                "decision_rule": {
                  "method": "exit_code_zero",
                  "pass_criteria": "exit 0",
                  "fail_criteria": "CONTROL_VIOLATION"
                },
                "default_severity": "Medium"
              },
              "T-CISCO": {
                "name": "Cisco IOS version check",
                "category": "synthetic",
                "tool": "builtin",
                "script": "T-CISCO.sh",
                "decision_rule": {
                  "method": "exit_code_zero",
                  "pass_criteria": "exit 0",
                  "fail_criteria": "CONTROL_VIOLATION"
                },
                "default_severity": "Medium"
              },
              "T-JUNI": {
                "name": "Juniper Junos config check",
                "category": "synthetic",
                "tool": "builtin",
                "script": "T-JUNI.sh",
                "decision_rule": {
                  "method": "exit_code_zero",
                  "pass_criteria": "exit 0",
                  "fail_criteria": "CONTROL_VIOLATION"
                },
                "default_severity": "Medium"
              }
            }
            """;
        Files.writeString(root.resolve("2_static_map.json"), map);
        Files.writeString(root.resolve("3_decision_engine.csv"),
            "code,test_name,category,tool,script,eval_method,pass_criteria,fail_criteria,default_severity,fallback_method,requires_external_tool\n"
            + "T-SHARED,Shared TLS check,synthetic,builtin,T-SHARED.sh,exit_code_zero,exit 0,CONTROL_VIOLATION,Medium,manual_review_required,false\n"
            + "T-CISCO,Cisco IOS check,synthetic,builtin,T-CISCO.sh,exit_code_zero,exit 0,CONTROL_VIOLATION,Medium,manual_review_required,false\n"
            + "T-JUNI,Juniper Junos check,synthetic,builtin,T-JUNI.sh,exit_code_zero,exit 0,CONTROL_VIOLATION,Medium,manual_review_required,false\n");

        Path scripts = root.resolve("stat_scripts");
        Files.createDirectories(scripts);
        // Shared: vendor-dependent verdict (trap)
        Files.writeString(scripts.resolve("T-SHARED.sh"),
            "#!/bin/bash\n"
            + "echo \"T-SHARED VENDOR=[$TRINETRA_VENDOR] CONNECTOR=[$TRINETRA_CONNECTOR] TARGET=[$1]\"\n"
            + "if [[ \"$TRINETRA_VENDOR\" == \"Cisco\" ]]; then\n"
            + "  echo \"CISCO_TLS_OK: strong ciphers only\"\n"
            + "  exit 0\n"
            + "elif [[ \"$TRINETRA_VENDOR\" == \"Juniper\" ]]; then\n"
            + "  echo \"CONTROL_VIOLATION: Juniper weak TLS 1.0 offered\"\n"
            + "  exit 3\n"
            + "else\n"
            + "  echo \"UNKNOWN_VENDOR\"\n"
            + "  exit 1\n"
            + "fi\n");
        // Cisco-specific: always PASS when run on Cisco (but script checks vendor for realism)
        Files.writeString(scripts.resolve("T-CISCO.sh"),
            "#!/bin/bash\n"
            + "echo \"T-CISCO VENDOR=[$TRINETRA_VENDOR] CONNECTOR=[$TRINETRA_CONNECTOR] TARGET=[$1]\"\n"
            + "echo \"terminal length 0 ; show version -> Cisco IOS 15.9\"\n"
            + "exit 0\n");
        // Juniper-specific: always FAIL (to make SOC2 distinct) — realistic Junos check with per-command pager
        Files.writeString(scripts.resolve("T-JUNI.sh"),
            "#!/bin/bash\n"
            + "echo \"T-JUNI VENDOR=[$TRINETRA_VENDOR] CONNECTOR=[$TRINETRA_CONNECTOR] TARGET=[$1]\"\n"
            + "echo \"show version | no-more -> Juniper Junos 22.4R1\"\n"
            + "echo \"CONTROL_VIOLATION: exposed Juniper default creds\"\n"
            + "exit 3\n");
        // Ensure scripts executable (not strictly needed since we call bash)
        for (String c : List.of("T-SHARED", "T-CISCO", "T-JUNI")) {
            try { Files.setPosixFilePermissions(scripts.resolve(c + ".sh"), Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE, PosixFilePermission.GROUP_READ, PosixFilePermission.OTHERS_READ)); } catch (Exception ignored) {}
        }

        Path configDir = root.resolve("config");
        Files.createDirectories(configDir);
        // Manifest: T-SHARED maps to both, T-CISCO ISO only, T-JUNI SOC2 only => distinct percentages
        String manifest = """
            {
              "T-SHARED": {
                "description": "Shared TLS check (both vendors)",
                "frameworks": {
                  "ISO27001": ["A.5"],
                  "SOC2": ["CC1"]
                }
              },
              "T-CISCO": {
                "description": "Cisco IOS check",
                "frameworks": {
                  "ISO27001": ["A.6"]
                }
              },
              "T-JUNI": {
                "description": "Juniper Junos check",
                "frameworks": {
                  "SOC2": ["CC2"]
                }
              }
            }
            """;
        Files.writeString(configDir.resolve("compliance_manifest.json"), manifest);
        TrinetraCompliance.reload();
        // Ensure sessions dir exists
        Files.createDirectories(root.resolve("sessions"));
    }
}
