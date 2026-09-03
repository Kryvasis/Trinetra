import java.nio.file.*;
import java.util.*;

/**
 * Deterministic compliance scorer for Trinetra sessions.
 *
 * Given a session name, reads normalized_results from the tamper-evident
 * brain-state chain, cross-references each test_id against the compliance
 * manifest, and produces a structured per-framework scoring report.
 *
 * This is a pure data transformation — no AI, no LLM calls.
 * Output is a separate artifact (not part of the brain-state hash chain).
 */
public class TrinetraComplianceScorer {

    /** Threshold: controls below this % are flagged as coverage gaps. */
    private static final double COVERAGE_GAP_THRESHOLD = 100.0;

    /**
     * Main scoring entry point. Reads session brain-state, scores against
     * the compliance manifest, writes a JSON report to the session directory.
     *
     * @param sessionName the session to score
     * @return the scoring result as a structured map
     */
    public static Map<String, Object> score(String sessionName) {
        return score(sessionName, null);
    }

    /**
     * Filtered scoring entry point. If frameworkFilter is null or empty, all
     * frameworks in the manifest are scored. Otherwise only the requested
     * framework keys (case-insensitive, underscores/hyphens tolerant) are
     * included in the output. This enables the PS-required "user-selected benchmarks"
     * without breaking existing callers that pass no filter.
     *
     * @param sessionName the session to score
     * @param frameworkFilter optional set of framework keys to include (e.g. CIS, STIG, NIST_800-53)
     * @return the scoring result as a structured map (filtered)
     */
    public static Map<String, Object> score(String sessionName, Set<String> frameworkFilter) {
        String sanitized = TrinetraCommon.sanitizeName(sessionName);
        Set<String> normalizedFilter = normalizeFrameworkFilter(frameworkFilter);

        List<Map<String, Object>> results =
            TrinetraSession.getNormalizedResults(sanitized);

        Set<String> allManifestIds = TrinetraCompliance.getMappedTestIds();

        // ── Per-framework accumulation ──
        // framework -> { controls_covered: Set, tests_passed: int, tests_failed: int,
        //                tests_manual_review: int, total_mapped: int }
        Map<String, FrameworkAccumulator> accumulators = new LinkedHashMap<>();

        List<String> unmappedTests = new ArrayList<>();

        for (Map<String, Object> entry : results) {
            String testId = TrinetraCommon.getString(entry, "test_id", "");
            String verdict = TrinetraCommon.getString(entry, "normalized_result", "");

            Map<String, List<String>> controlMappings =
                TrinetraCompliance.getControlMappings(testId);

            if (controlMappings.isEmpty()) {
                // Test was executed but has no compliance mapping
                unmappedTests.add(testId);
                continue;
            }

            boolean isPassed = isPassingVerdict(verdict);

            for (Map.Entry<String, List<String>> fw : controlMappings.entrySet()) {
                String framework = fw.getKey();
                if (normalizedFilter != null && !normalizedFilter.contains(normalizeFrameworkKey(framework))) {
                    continue;
                }
                List<String> controlIds = fw.getValue();

                FrameworkAccumulator acc = accumulators.computeIfAbsent(
                    framework, k -> new FrameworkAccumulator());
                acc.controlsCovered.addAll(controlIds);
                acc.totalMapped++;
                if (isPassed) {
                    acc.testsPassed++;
                } else {
                    // Unresolved evidence remains in the denominator, but is not a failure.
                    switch (verdict.trim().toLowerCase(Locale.ROOT)) {
                        case "fail": acc.testsFailed++; break;
                        case "error": acc.testsErrors++; break;
                        case "not_tested": acc.testsNotTested++; break;
                        default: acc.testsManualReview++;
                    }
                }
            }
        }

        // When a filter is active, ensure selected frameworks are represented even if
        // no executed test mapped to them (shows 0% + full coverage_gaps honestly).
        if (normalizedFilter != null) {
            Set<String> canonicalFrameworks = new LinkedHashSet<>();
            for (String tid : TrinetraCompliance.getMappedTestIds()) {
                for (String fw : TrinetraCompliance.getControlMappings(tid).keySet()) {
                    canonicalFrameworks.add(fw);
                }
            }
            for (String canon : canonicalFrameworks) {
                if (normalizedFilter.contains(normalizeFrameworkKey(canon)) && !accumulators.containsKey(canon)) {
                    accumulators.put(canon, new FrameworkAccumulator());
                }
            }
        }

        // ── Detect control coverage gaps ──
        // For each framework, find control IDs present in the manifest
        // that were NOT covered by any executed test in this session.
        // When a filter is active, gaps are computed only for the selected frameworks.
        Map<String, List<String>> coverageGaps = detectCoverageGaps(accumulators, normalizedFilter);

        // ── Build output ──
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("session_name", sanitized);
        output.put("score_basis", "Mapped-check pass rate, not framework compliance or certification. Unresolved checks remain in the denominator; mappings do not prove control effectiveness.");

        Map<String, Object> frameworks = new LinkedHashMap<>();
        for (Map.Entry<String, FrameworkAccumulator> e : accumulators.entrySet()) {
            FrameworkAccumulator acc = e.getValue();
            Map<String, Object> fw = new LinkedHashMap<>();
            List<String> sortedControls = new ArrayList<>(acc.controlsCovered);
            Collections.sort(sortedControls);
            fw.put("controls_covered", sortedControls);
            fw.put("tests_passed", acc.testsPassed);
            fw.put("tests_failed", acc.testsFailed);
            fw.put("tests_manual_review", acc.testsManualReview);
            fw.put("tests_errors", acc.testsErrors);
            fw.put("tests_not_tested", acc.testsNotTested);
            fw.put("tests_not_passed", acc.totalMapped - acc.testsPassed);
            fw.put("total_tests_mapped", acc.totalMapped);
            double pct = acc.totalMapped > 0
                ? Math.round(acc.testsPassed * 1000.0 / acc.totalMapped) / 10.0
                : 0.0;
            fw.put("compliance_percentage", pct);

            List<String> gaps = coverageGaps.getOrDefault(e.getKey(), Collections.emptyList());
            fw.put("coverage_gaps", gaps);

            frameworks.put(e.getKey(), fw);
        }
        output.put("frameworks", frameworks);

        // Sort unmapped tests for deterministic output
        List<String> sortedUnmapped = new ArrayList<>(unmappedTests);
        Collections.sort(sortedUnmapped);
        output.put("unmapped_tests", sortedUnmapped);

        output.put("total_tests_executed", results.size());
        output.put("generated_at", TrinetraCommon.nowIso());

        return output;
    }

    /**
     * Score a session and write the result to a JSON file in the session directory.
     *
     * @param sessionName the session to score
     * @return the path to the written file
     */
    public static Path scoreAndWrite(String sessionName) {
        return scoreAndWrite(sessionName, null);
    }

    /**
     * Filtered scoreAndWrite. When filter is null/empty, writes the canonical
     * compliance_score_&lt;session&gt;.json. When filter is non-empty, writes a
     * transient filtered file and also returns its path so callers can still
     * locate an artifact without clobbering the canonical file.
     */
    public static Path scoreAndWrite(String sessionName, Set<String> frameworkFilter) {
        String sanitized = TrinetraCommon.sanitizeName(sessionName);
        Map<String, Object> result = score(sanitized, frameworkFilter);
        if (frameworkFilter == null || frameworkFilter.isEmpty()) {
            Path outPath = TrinetraCommon.sessionDir(sanitized)
                .resolve("compliance_score_" + sanitized + ".json");
            TrinetraCommon.writeJsonFile(outPath, result);
            return outPath;
        } else {
            // Write filtered variant to avoid clobbering canonical file
            String suffix = String.join("_", normalizeFrameworkFilter(frameworkFilter));
            Path outPath = TrinetraCommon.sessionDir(sanitized)
                .resolve("compliance_score_" + sanitized + "_filtered_" + suffix + ".json");
            TrinetraCommon.writeJsonFile(outPath, result);
            return outPath;
        }
    }

    // ── Framework filter helpers ──
    private static Set<String> normalizeFrameworkFilter(Set<String> filter) {
        if (filter == null || filter.isEmpty()) return null;
        Set<String> out = new LinkedHashSet<>();
        for (String f : filter) {
            if (f == null) continue;
            String n = normalizeFrameworkKey(f.trim());
            if (!n.isEmpty()) out.add(n);
        }
        return out.isEmpty() ? null : out;
    }

    private static String normalizeFrameworkKey(String key) {
        return key.toLowerCase().replaceAll("[\\s\\-]", "_");
    }

    /**
     * Determine whether a normalized_result verdict counts as "passing"
     * for compliance scoring.
     *
     * Uses the same verdict strings that TrinetraStat.Verdict.name().toLowerCase()
     * writes into normalized_results.
     */
    private static boolean isPassingVerdict(String verdict) {
        if (verdict == null) return false;
        String v = verdict.trim().toLowerCase();
        return "pass".equals(v) || "success".equals(v);
    }

    /**
     * Detect control coverage gaps: for each framework in scope, find all
     * control IDs mentioned anywhere in the manifest that were NOT covered
     * by the executed tests in this session.
     *
     * Returns null for frameworks that have no gaps.
     */
    private static Map<String, List<String>> detectCoverageGaps(
            Map<String, FrameworkAccumulator> accumulators) {
        return detectCoverageGaps(accumulators, null);
    }

    private static Map<String, List<String>> detectCoverageGaps(
            Map<String, FrameworkAccumulator> accumulators, Set<String> normalizedFilter) {

        Map<String, List<String>> gaps = new LinkedHashMap<>();

        // Collect all control IDs per framework across the entire manifest
        Map<String, Set<String>> allControlsByFramework = new LinkedHashMap<>();
        Set<String> allIds = TrinetraCompliance.getMappedTestIds();
        for (String testId : allIds) {
            Map<String, List<String>> mappings =
                TrinetraCompliance.getControlMappings(testId);
            for (Map.Entry<String, List<String>> fw : mappings.entrySet()) {
                if (normalizedFilter != null && !normalizedFilter.contains(normalizeFrameworkKey(fw.getKey()))) {
                    continue;
                }
                allControlsByFramework
                    .computeIfAbsent(fw.getKey(), k -> new LinkedHashSet<>())
                    .addAll(fw.getValue());
            }
        }

        // For each framework in the accumulator, find which controls are uncovered
        for (Map.Entry<String, FrameworkAccumulator> e : accumulators.entrySet()) {
            String framework = e.getKey();
            Set<String> covered = e.getValue().controlsCovered;
            Set<String> allControls = allControlsByFramework.getOrDefault(
                framework, Collections.emptySet());

            List<String> uncovered = new ArrayList<>();
            for (String control : allControls) {
                if (!covered.contains(control)) {
                    uncovered.add(control);
                }
            }
            Collections.sort(uncovered);
            if (!uncovered.isEmpty()) {
                gaps.put(framework, uncovered);
            }
        }

        return gaps;
    }

    /**
     * Internal accumulator for per-framework scoring.
     */
    private static class FrameworkAccumulator {
        final Set<String> controlsCovered = new LinkedHashSet<>();
        int testsPassed = 0;
        int testsFailed = 0;
        int testsManualReview = 0;
        int testsErrors = 0;
        int testsNotTested = 0;
        int totalMapped = 0;
    }
}
