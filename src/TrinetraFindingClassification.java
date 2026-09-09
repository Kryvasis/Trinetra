import java.util.*;

/**
 * Four-way finding classification (review item 1b).
 *
 * Every finding shown to a user — Results view, markdown report, PDF —
 * carries exactly one of these labels:
 *
 *   confirmed risk        — Category 1 config-syntax check found the insecure
 *                           directive present (or a live probe failed).
 *   verified pass         — Category 1 check found the secure directive present
 *                           (or a live probe passed).
 *   insufficient evidence — a Category 1 check ran but the config contained
 *                           neither the insecure nor the secure directive, so
 *                           neither pass nor risk can be established. Distinct
 *                           from "not applicable".
 *   unsupported check     — Category 2 (requires live verification), an
 *                           unimplemented/stub check (error/not_tested), or the
 *                           UNRECOGNIZED pseudo-finding. No verdict is possible
 *                           from this evidence type.
 *
 * Computed on the fly from (testId, normalized_result, assessment_kind) so
 * historical chain entries classify identically without data migration.
 * Cisco IOS is the only fully supported observation-layer vendor (see
 * TrinetraConfigObservations); classification itself is vendor-agnostic and
 * Juniper/other vendors are NOT downgraded here — the parser-scope gap is
 * disclosed separately in the report/UI, not by relabeling.
 */
public final class TrinetraFindingClassification {

    public static final String CONFIRMED_RISK = "confirmed risk";
    public static final String VERIFIED_PASS = "verified pass";
    public static final String INSUFFICIENT_EVIDENCE = "insufficient evidence";
    public static final String UNSUPPORTED_CHECK = "unsupported check";

    private TrinetraFindingClassification() {}

    /**
     * Classify one normalized-result style verdict.
     *
     * @param testId           V-code (or UNRECOGNIZED)
     * @param normalizedResult pass|fail|manual_review|error|not_tested|success...
     * @param assessmentKind   chain field: "configuration_only" for config ingest,
     *                         "live_probe" for stat-script probes (or "" when unknown)
     */
    public static String classify(String testId, String normalizedResult, String assessmentKind) {
        String tid = testId != null ? testId.trim().toUpperCase(Locale.ROOT) : "";
        String v = normalizedResult != null ? normalizedResult.trim().toLowerCase(Locale.ROOT) : "";
        String kind = assessmentKind != null ? assessmentKind.trim().toLowerCase(Locale.ROOT) : "";

        // UNRECOGNIZED lines and unmapped/stub outcomes can never resolve.
        if ("UNRECOGNIZED".equals(tid)) return UNSUPPORTED_CHECK;
        if ("error".equals(v) || "not_tested".equals(v)) return UNSUPPORTED_CHECK;

        // Category 2 inherently requires live state — config text cannot prove it.
        // Live-probe evidence IS live state, so pass/fail there still count.
        boolean isLiveProbe = "live_probe".equals(kind) || "stat_script".equals(kind);
        if (TrinetraConfigIngestor.isConfigCategory2(tid) && !isLiveProbe) return UNSUPPORTED_CHECK;

        // Category 1 config-native outcomes (and all live-probe outcomes).
        if ("fail".equals(v)) return CONFIRMED_RISK;
        if ("pass".equals(v) || "success".equals(v)) return VERIFIED_PASS;

        // Ran but neither directive present (config) or no decision (probe).
        if (isLiveProbe) return INSUFFICIENT_EVIDENCE;
        return INSUFFICIENT_EVIDENCE;
    }

    /** Convenience overload for scorer/report rows carrying a full entry map. */
    public static String classifyEntry(Map<String, Object> entry) {
        if (entry == null) return UNSUPPORTED_CHECK;
        return classify(
            TrinetraCommon.getString(entry, "test_id",
                TrinetraCommon.getString(entry, "v_code",
                    TrinetraCommon.getString(entry, "test_code", ""))),
            TrinetraCommon.getString(entry, "normalized_result",
                TrinetraCommon.getString(entry, "verdict",
                    TrinetraCommon.getString(entry, "result", ""))),
            TrinetraCommon.getString(entry, "assessment_kind", ""));
    }

    /** Comparison transitions (review item 2) expressed in the same four terms. */
    public static String transition(String beforeClass, String afterClass) {
        if (CONFIRMED_RISK.equals(beforeClass) && VERIFIED_PASS.equals(afterClass))
            return "resolved";
        if (VERIFIED_PASS.equals(beforeClass) && CONFIRMED_RISK.equals(afterClass))
            return "newly failing";
        if ((INSUFFICIENT_EVIDENCE.equals(beforeClass) || UNSUPPORTED_CHECK.equals(beforeClass))
            && (INSUFFICIENT_EVIDENCE.equals(afterClass) || UNSUPPORTED_CHECK.equals(afterClass)))
            return "still unresolved";
        if (Objects.equals(beforeClass, afterClass)) return "unchanged";
        return "unchanged";
    }
}
