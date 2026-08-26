import java.nio.file.*;
import java.util.*;
import java.util.regex.*;

/**
 * LLM narrative layer on top of TrinetraComplianceScorer output (Prompt 16).
 *
 * The scorer (Prompt 15) is deterministic and already correct. This module
 * ONLY explains and contextualizes that data. Hard rules enforced here:
 *
 *  1. The LLM is never the source of numbers. The exact scorer JSON goes
 *     into the prompt with instructions to reproduce values verbatim.
 *  2. Every numeric token in the LLM response is validated against the set
 *     of numbers present in the scorer output (percentages, pass/fail
 *     counts, mapped totals, control counts, unmapped count, executed
 *     total). Any foreign digit -> rejection.
 *  3. One strict retry with a correction instruction; after a second
 *     failure (or any LLM unavailability: no key, offline, timeout) a
 *     deterministic template narrative built purely from scorer data is
 *     used instead, and the report is labeled accordingly.
 *  4. Output artifact: sessions/<name>/compliance_narrative_<name>.md.
 *     Like the Prompt 15 scoring JSON, this is a DERIVED report — it must
 *     NOT be added to BRAIN_STATE_REQUIRED or the normalized_results hash
 *     chain. Nothing in this class touches brain state.
 *
 * LLM client: reuses the existing TrinetraCommon.execGemini pattern
 * (Gemini CLI first, OpenRouter fallback, central pacing). A injectable
 * seam (setLlmCall) exists purely for tests.
 */
public class TrinetraNarrativeGenerator {

    /** Injectable LLM endpoint; defaults to the standard execGemini path. */
    public interface LlmCall {
        String apply(String prompt);
    }

    private static volatile LlmCall llmCall = TrinetraCommon::execGemini;

    /** Test-only seam: replace the LLM transport with a mock. */
    public static void setLlmCall(LlmCall call) {
        llmCall = (call == null) ? TrinetraCommon::execGemini : call;
    }

    /** Restore the real Gemini/OpenRouter transport. */
    public static void resetLlmCall() {
        llmCall = TrinetraCommon::execGemini;
    }

    public static final String SOURCE_LLM = "gemini_llm_validated";
    public static final String SOURCE_TEMPLATE = "template_fallback";

    // ── Entry point ──────────────────────────────────────────────────

    /**
     * Generate the combined compliance narrative report for a session from
     * an already-computed TrinetraComplianceScorer result. Writes
     * sessions/<name>/compliance_narrative_<name>.md and returns metadata:
     * {session_name, target, source, attempts, fallback_reason,
     *  rejected_numbers_first_attempt, path}.
     */
    public static Map<String, Object> generateReport(String sessionName,
                                                     Map<String, Object> scoreData) {
        String sanitized = TrinetraCommon.sanitizeName(sessionName);

        if (scoreData == null || scoreData.isEmpty()) {
            throw new IllegalArgumentException(
                "scorer output is null/empty for session " + sanitized);
        }

        // Per-test supporting context + per-framework failed/passed lists.
        List<String> perTestLines = new ArrayList<>();
        Map<String, List<String>> failedByFw = new LinkedHashMap<>();
        Map<String, List<String>> passedByFw = new LinkedHashMap<>();
        buildPerTestContext(sanitized, perTestLines, failedByFw, passedByFw);

        Set<Double> expected = collectExpectedNumbers(scoreData);
        String allowedList = renderAllowedValues(scoreData);

        String basePrompt = buildBasePrompt(sanitized, scoreData, allowedList, perTestLines);

        // ── Attempt 1 ──
        int attempts = 1;
        String first = safeLlm(basePrompt);
        ValidationResult v1 = validateNarrative(first, scoreData, expected);

        String source;
        String body;
        String fallbackReason = null;
        List<String> rejectedFirst = null;
        List<String> rejectedSecond = null;

        if (v1.ok && first != null) {
            source = SOURCE_LLM;
            body = first.strip();
        } else {
            rejectedFirst = v1.offenders;

            // ── Attempt 2: stricter correction instruction ──
            attempts = 2;
            String retryPrompt = buildRetryPrompt(basePrompt, v1, allowedList);
            String second = safeLlm(retryPrompt);
            ValidationResult v2 = validateNarrative(second, scoreData, expected);

            if (v2.ok && second != null) {
                source = SOURCE_LLM;
                body = second.strip();
                TrinetraCommon.logInfo("Narrative accepted on retry for " + sanitized);
            } else {
                rejectedSecond = v2.offenders;
                source = SOURCE_TEMPLATE;
                boolean llmSilent = (first == null && second == null);
                fallbackReason = llmSilent
                    ? "Template fallback (LLM unavailable: no API key / offline / API error)"
                    : "Template fallback (LLM narrative rejected twice by number validation)";
                body = buildTemplateBody(scoreData, failedByFw, passedByFw);
                TrinetraCommon.logWarn("Narrative fallback for " + sanitized
                    + ": " + fallbackReason
                    + " offenders#1=" + rejectedFirst
                    + " offenders#2=" + rejectedSecond);
            }
        }

        String target = resolveTarget(sanitized);
        String report = assembleReport(sanitized, target, scoreData,
            source, attempts, fallbackReason, body);

        Path outPath = TrinetraCommon.sessionDir(sanitized)
            .resolve("compliance_narrative_" + sanitized + ".md");
        TrinetraCommon.atomicWriteFile(outPath, report);

        Map<String, Object> meta = TrinetraCommon.newMap();
        meta.put("session_name", sanitized);
        meta.put("target", target);
        meta.put("source", source);
        meta.put("attempts", attempts);
        meta.put("fallback_reason", fallbackReason == null ? "" : fallbackReason);
        meta.put("rejected_numbers_first_attempt", rejectedFirst == null ? new ArrayList<String>() : rejectedFirst);
        meta.put("rejected_numbers_second_attempt", rejectedSecond == null ? new ArrayList<String>() : rejectedSecond);
        meta.put("path", outPath.toString());
        return meta;
    }

    private static String safeLlm(String prompt) {
        try {
            return llmCall.apply(prompt);
        } catch (Exception e) {
            TrinetraCommon.logWarn("LLM call failed: " + e.getMessage());
            return null;
        }
    }

    private static String resolveTarget(String sessionName) {
        Map<String, Object> session = TrinetraSession.loadSession(sessionName);
        return session != null
            ? TrinetraCommon.getString(session, "target", "unknown")
            : "unknown";
    }

    // ── Per-test context (deterministic, from brain state + manifest) ──

    @SuppressWarnings("unchecked")
    private static void buildPerTestContext(String sessionName,
                                            List<String> perTestLines,
                                            Map<String, List<String>> failedByFw,
                                            Map<String, List<String>> passedByFw) {
        List<Map<String, Object>> results =
            TrinetraSession.getNormalizedResults(sessionName);
        for (Map<String, Object> entry : results) {
            String testId = TrinetraCommon.getString(entry, "test_id", "?");
            String verdict = TrinetraCommon.getString(entry, "normalized_result", "");
            Map<String, List<String>> mappings =
                TrinetraCompliance.getControlMappings(testId);

            boolean passing = "pass".equalsIgnoreCase(verdict)
                || "success".equalsIgnoreCase(verdict);
            for (String fw : mappings.keySet()) {
                (passing ? passedByFw : failedByFw)
                    .computeIfAbsent(fw, k -> new ArrayList<>())
                    .add(testId);
            }
            perTestLines.add("- " + testId + " -> verdict=" + verdict
                + (mappings.isEmpty()
                    ? " (no framework mapping)"
                    : " (maps to: " + String.join(", ", mappings.keySet()) + ")"));
        }
        Collections.sort(perTestLines);
    }

    // ── Expected-number collection (the ONLY writable digits) ───────

    @SuppressWarnings("unchecked")
    static Set<Double> collectExpectedNumbers(Map<String, Object> scoreData) {
        Set<Double> out = new HashSet<>();
        Map<String, Object> frameworks = TrinetraCommon.getMap(scoreData, "frameworks");
        for (Map.Entry<String, Object> e : frameworks.entrySet()) {
            if (!(e.getValue() instanceof Map)) continue;
            Map<String, Object> fm = (Map<String, Object>) e.getValue();
            addNum(out, fm.get("compliance_percentage"));
            addNum(out, fm.get("tests_passed"));
            addNum(out, fm.get("tests_failed"));
            addNum(out, fm.get("total_tests_mapped"));
            Object covered = fm.get("controls_covered");
            if (covered instanceof List) out.add((double) ((List<?>) covered).size());
            Object gaps = fm.get("coverage_gaps");
            if (gaps instanceof List) out.add((double) ((List<?>) gaps).size());
        }
        Object unmapped = scoreData.get("unmapped_tests");
        if (unmapped instanceof List) out.add((double) ((List<?>) unmapped).size());
        addNum(out, scoreData.get("total_tests_executed"));
        return out;
    }

    private static void addNum(Set<Double> set, Object v) {
        if (v instanceof Number) set.add(((Number) v).doubleValue());
    }

    private static String renderAllowedValues(Map<String, Object> scoreData) {
        StringBuilder sb = new StringBuilder();
        Map<String, Object> frameworks = TrinetraCommon.getMap(scoreData, "frameworks");
        for (Map.Entry<String, Object> e : frameworks.entrySet()) {
            if (!(e.getValue() instanceof Map)) continue;
            @SuppressWarnings("unchecked")
            Map<String, Object> fm = (Map<String, Object>) e.getValue();
            if (sb.length() > 0) sb.append("; ");
            sb.append(e.getKey()).append(":")
              .append(" compliance_percentage=").append(fm.getOrDefault("compliance_percentage", "?"))
              .append(", tests_passed=").append(fm.getOrDefault("tests_passed", "?"))
              .append(", tests_failed=").append(fm.getOrDefault("tests_failed", "?"))
              .append(", total_tests_mapped=").append(fm.getOrDefault("total_tests_mapped", "?"))
              .append(", controls_covered_count=").append(listSize(fm.get("controls_covered")))
              .append(", coverage_gaps_count=").append(listSize(fm.get("coverage_gaps")));
        }
        if (sb.length() > 0) sb.append("; ");
        sb.append("unmapped_tests_count=").append(listSize(scoreData.get("unmapped_tests")));
        sb.append("; total_tests_executed=").append(scoreData.getOrDefault("total_tests_executed", "?"));
        return sb.toString();
    }

    private static int listSize(Object v) {
        return v instanceof List ? ((List<?>) v).size() : 0;
    }

    // ── Prompt construction ──────────────────────────────────────────

    private static String buildBasePrompt(String sessionName,
                                          Map<String, Object> scoreData,
                                          String allowedList,
                                          List<String> perTestLines) {
        StringBuilder p = new StringBuilder();
        p.append("You are a compliance reporting assistant for the Trinetra pentest framework.\n\n");
        p.append("SCORER OUTPUT (deterministic, EXACT and FINAL — the authoritative data):\n");
        p.append(TrinetraJson.prettyJson(scoreData)).append("\n\n");
        p.append("PER-TEST SUPPORTING CONTEXT (reference test IDs verbatim; do NOT derive any new numbers from this section):\n");
        if (perTestLines.isEmpty()) p.append("- (none)\n");
        else p.append(String.join("\n", perTestLines)).append("\n");
        p.append("\nNUMBER RULES (STRICT):\n");
        p.append("1. All numeric values in the scorer output are final. Reproduce every number you mention EXACTLY as given — never recalculate, round, convert units, average, estimate, or invent numbers.\n");
        p.append("2. You may write ONLY these exact numeric values, character-for-character:\n   ")
          .append(allowedList).append("\n");
        p.append("3. Write NO other digits anywhere in your response: no dates, no times, no years, no version numbers, no port numbers, no numbered headings or numbered lists (use \"###\" headings and \"-\" bullets only), no TLS/cipher versions. Spell incidental small quantities as words (for example: \"two\", \"one\") — but NEVER spell out the permitted values above in words: every framework's compliance_percentage MUST appear exactly as written (for example 66.7%, never \"fifty percent\").\n");
        p.append("4. Percentages keep exactly the decimals given (write 66.7%, never 67% or 66.67%).\n\n");
        p.append("REQUIRED STRUCTURE (plain markdown, no code fences):\n");
        p.append("For EACH framework present under \"frameworks\" in the scorer output, one section:\n");
        p.append("### <Framework name>\n");
        p.append("- Compliance posture: short plain-language summary using that framework's compliance_percentage exactly.\n");
        p.append("- Failed tests: name the failing test_ids for this framework from the supporting context and explain practically what failing them means for this framework's controls. If none failed, say so plainly.\n");
        p.append("- Coverage gaps: state how many controls were not exercised (use coverage_gaps_count exactly) and what that means for assurance.\n");
        p.append("Then ONE short paragraph interpreting unmapped_tests: these tests were executed but are not yet mapped in the compliance manifest, so they are NOT counted as compliance failures — they are mapping backlog only.\n");
        p.append("Return ONLY the markdown narrative text.\n");
        return p.toString();
    }

    private static String buildRetryPrompt(String basePrompt,
                                           ValidationResult v1,
                                           String allowedList) {
        StringBuilder p = new StringBuilder(basePrompt);
        p.append("\n\nCRITICAL CORRECTION — YOUR PREVIOUS RESPONSE WAS REJECTED BY AUTOMATED NUMBER VALIDATION.\n");
        p.append("Offending numeric values found in your response (these do NOT exist in the scorer data): ");
        p.append(v1.offenders.isEmpty() ? "(none)" : v1.offenders.toString()).append("\n");
        if (!v1.missing.isEmpty()) {
            p.append("Required figures you OMITTED or spelled out instead of writing numerically: ")
             .append(v1.missing.toString()).append("\n");
        }
        p.append("You may use ONLY these exact numeric values:\n   ").append(allowedList).append("\n");
        p.append("Every framework's compliance_percentage is MANDATORY and must appear exactly as listed.\n");
        p.append("Regenerate the FULL corrected narrative now. Copy every permitted number character-for-character; write zero other digits anywhere.");
        return p.toString();
    }

    // ── Strict number validation ─────────────────────────────────────

    /** Outcome of validateNarrative. */
    static class ValidationResult {
        final boolean ok;
        final List<String> offenders;
        final List<String> missing;
        ValidationResult(boolean ok, List<String> offenders, List<String> missing) {
            this.ok = ok;
            this.offenders = offenders;
            this.missing = missing;
        }
    }

    /**
     * Verify every numeric value mentioned in the narrative exactly matches
     * a value from the scorer output, AND that no framework's
     * compliance_percentage was silently dropped (a digit-free narrative
     * would otherwise pass vacuously and lose the key figures).
     * Non-semantic digits (control IDs like AC-4 or 1.2.1, test IDs like
     * V-004, framework names like NIST_800-53, ISO timestamps, the session
     * name, markdown enumerators) are stripped before scanning so only
     * genuine claims are checked.
     */
    static ValidationResult validateNarrative(String narrative,
                                              Map<String, Object> scoreData,
                                              Set<Double> expected) {
        if (narrative == null || narrative.isBlank()) {
            return new ValidationResult(false,
                new ArrayList<>(List.of("<empty response>")),
                new ArrayList<>());
        }

        String text = stripNonSemantic(narrative, scoreData);

        List<String> offenders = new ArrayList<>();
        Set<Double> matched = new HashSet<>();
        Matcher m = NUM_TOKEN.matcher(text);
        while (m.find()) {
            int end = m.end();
            if (!isCleanRightBoundary(text, end)) continue;   // part of larger token
            String tok = m.group();
            double val;
            try { val = Double.parseDouble(tok); }
            catch (NumberFormatException nfe) { continue; }
            if (!containsExact(expected, val)) {
                int ctxStart = Math.max(0, m.start() - 24);
                int ctxEnd = Math.min(text.length(), m.end() + 24);
                offenders.add(tok + " (context: ..."
                    + text.substring(ctxStart, ctxEnd).replaceAll("\\s+", " ") + "...)");
            } else {
                matched.add(val);
            }
        }

        // Mandatory figures: every framework's compliance_percentage must be
        // present as an exact numeric token, not spelled out or omitted.
        List<String> missing = new ArrayList<>();
        for (Map.Entry<String, Object> e : TrinetraCommon.getMap(scoreData, "frameworks").entrySet()) {
            if (!(e.getValue() instanceof Map)) continue;
            Object pctObj = ((Map<?, ?>) e.getValue()).get("compliance_percentage");
            if (!(pctObj instanceof Number)) continue;
            double pct = ((Number) pctObj).doubleValue();
            if (!containsExact(matched, pct)) {
                missing.add(e.getKey() + " compliance_percentage=" + pctObj
                    + " not stated numerically");
            }
        }

        return new ValidationResult(offenders.isEmpty() && missing.isEmpty(),
            offenders, missing);
    }

    private static final Pattern NUM_TOKEN =
        Pattern.compile("(?<![\\w./+\\-])(\\d+(?:\\.\\d+)?)");

    /** Allow sentence-final punctuation and '%' right after a number. */
    private static boolean isCleanRightBoundary(String text, int end) {
        if (end >= text.length()) return true;
        char c = text.charAt(end);
        if (c == '.') {
            // "3." at sentence end is fine; "1.2" mid-number was already consumed by the regex.
            return !(end + 1 < text.length() && Character.isDigit(text.charAt(end + 1)));
        }
        // '%' is deliberately clean ("66.7%" must be validated); these are not:
        return !(Character.isLetterOrDigit(c) || c == '_' || c == '/' || c == '+' || c == '-');
    }

    private static boolean containsExact(Set<Double> expected, double val) {
        for (Double d : expected) {
            if (Math.abs(d - val) < 1e-9) return true;
        }
        return false;
    }

    /**
     * Remove everything whose digits are exempt from validation:
     * code fences, ISO timestamps, clock times, the session name,
     * framework names (NIST_800-53 etc.), control IDs, test IDs,
     * markdown enumerators.
     */
    private static String stripNonSemantic(String narrative, Map<String, Object> scoreData) {
        String text = narrative;

        // Fenced code blocks
        text = text.replaceAll("(?s)```.*?```", " ");

        // ISO-8601 timestamps and clock times
        text = text.replaceAll("\\d{4}-\\d{2}-\\d{2}(?:T[\\d:.]+Z?)?", " ");
        text = text.replaceAll("(?<!\\d)\\d{1,2}:\\d{2}(?::\\d{2})?(?!\\d)", " ");

        // Session name (sanitized and raw forms may carry digits)
        text = literalStrip(text, TrinetraCommon.getString(scoreData, "session_name", ""));
        text = literalStrip(text, scoreData.getOrDefault("session_name", "").toString());

        // Framework names and their human variants (SOC2, SOC 2, NIST_800-53, NIST 800-53 ...)
        for (String fw : TrinetraCommon.getMap(scoreData, "frameworks").keySet()) {
            text = literalStrip(text, fw);
            text = literalStrip(text, fw.replace("_", " "));
            text = literalStrip(text, fw.replace("_", "-"));
            text = literalStrip(text, fw.replace("-", " "));
            text = literalStrip(text, fw.replace("_", " ").replace("-", " "));
        }

        // Control IDs (covered + gap lists): A.13.1.1, AC-4, CC6.6, 1.2.1 ...
        // NOTE: raw List access here — TrinetraCommon.getList filters to
        // Map items only and would silently drop these string lists.
        Set<String> controlIds = new LinkedHashSet<>();
        for (Object fmObj : TrinetraCommon.getMap(scoreData, "frameworks").values()) {
            if (!(fmObj instanceof Map)) continue;
            @SuppressWarnings("unchecked")
            Map<String, Object> fm = (Map<String, Object>) fmObj;
            Object cov = fm.get("controls_covered");
            if (cov instanceof List) {
                for (Object c : (List<?>) cov) controlIds.add(String.valueOf(c));
            }
            Object gaps = fm.get("coverage_gaps");
            if (gaps instanceof List) {
                for (Object g : (List<?>) gaps) controlIds.add(String.valueOf(g));
            }
        }
        for (String id : controlIds) {
            if (id.isBlank()) continue;
            text = text.replaceAll("(?<![A-Za-z0-9])" + Pattern.quote(id) + "(?![A-Za-z0-9])", " ");
        }

        // Unmapped test IDs from the scorer output
        for (String t : TrinetraCommon.getStringList(scoreData, "unmapped_tests")) {
            text = literalStrip(text, t);
        }

        // Generic test-ID shape (V-004, T-201 ...) — covers per-test context refs
        text = text.replaceAll("(?<![A-Za-z0-9])[A-Z]{1,6}-\\d+(?![A-Za-z0-9])", " ");

        // Markdown enumerators ("1.", "2.3)", optionally after ### or bullets)
        text = text.replaceAll("(?m)^\\s*(?:#{1,6}\\s+)?(?:[-*+]\\s+)?\\d+(?:\\.\\d+)*[.)]\\s+", " ");

        return text;
    }

    /** Case-insensitive literal removal; no-op for blank needles. */
    private static String literalStrip(String text, String needle) {
        if (needle == null || needle.isBlank()) return text;
        return text.replaceAll("(?i)" + Pattern.quote(needle), " ");
    }

    // ── Template fallback (pure deterministic, zero LLM) ─────────────

    private static String buildTemplateBody(Map<String, Object> scoreData,
                                            Map<String, List<String>> failedByFw,
                                            Map<String, List<String>> passedByFw) {
        StringBuilder sb = new StringBuilder();
        Map<String, Object> frameworks = TrinetraCommon.getMap(scoreData, "frameworks");

        if (frameworks.isEmpty()) {
            sb.append("_No compliance-mapped frameworks scored for this session._\n\n");
        }

        for (Map.Entry<String, Object> e : frameworks.entrySet()) {
            if (!(e.getValue() instanceof Map)) continue;
            @SuppressWarnings("unchecked")
            Map<String, Object> fm = (Map<String, Object>) e.getValue();
            String fw = e.getKey();

            double pct = fm.get("compliance_percentage") instanceof Number
                ? ((Number) fm.get("compliance_percentage")).doubleValue() : 0.0;
            int passed = getIntOf(fm, "tests_passed");
            int failed = getIntOf(fm, "tests_failed");
            int mapped = getIntOf(fm, "total_tests_mapped");
            int controls = listSize(fm.get("controls_covered"));
            int gaps = listSize(fm.get("coverage_gaps"));

            sb.append("### ").append(fw).append("\n");
            sb.append("**Compliance posture:** ").append(fmtPct(pct))
              .append("% compliance — ").append(passed).append(" of ").append(mapped)
              .append(" mapped tests passed (").append(failed).append(" failed), covering ")
              .append(controls).append(" distinct controls.\n");

            List<String> failedTests = failedByFw.getOrDefault(fw, new ArrayList<>());
            sb.append("**Failed tests:** ");
            if (failedTests.isEmpty()) {
                sb.append("None — all tests mapped to this framework passed.\n");
            } else {
                sb.append(String.join(", ", failedTests)).append(".\n");
                sb.append("**Practical impact:** ").append(practicalImpact(fw)).append("\n");
            }

            sb.append("**Coverage gaps:** ").append(gaps)
              .append(gaps == 1 ? " control" : " controls")
              .append(" in this framework were not exercised by any executed test, limiting assurance for those areas.\n\n");
        }
        return sb.toString();
    }

    private static int getIntOf(Map<String, Object> m, String key) {
        Object v = m.get(key);
        if (v instanceof Number) return ((Number) v).intValue();
        try { return Integer.parseInt(String.valueOf(v)); }
        catch (Exception e) { return 0; }
    }

    private static String fmtPct(double d) {
        return d == Math.floor(d) ? String.valueOf((long) d) : String.valueOf(d);
    }

    private static String practicalImpact(String fw) {
        switch (fw) {
            case "ISO27001":
                return "the associated Annex A controls cannot currently be considered fully effective; treat the findings as ISMS nonconformities requiring corrective action.";
            case "NIST_800-53":
                return "the corresponding NIST security controls are not satisfied and should be remediated before an authority-to-operate decision.";
            case "PCI-DSS":
                return "cardholder-data-environment requirements may be violated, creating potential compliance liability with card brands.";
            case "SOC2":
                return "the related trust services criteria lack operating evidence, which auditors would flag as a control deficiency.";
            default:
                return "the associated controls remain at risk and should be remediated per vendor guidance.";
        }
    }

    // ── Report assembly ──────────────────────────────────────────────

    private static String assembleReport(String session, String target,
                                         Map<String, Object> scoreData,
                                         String source, int attempts,
                                         String fallbackReason, String body) {
        List<String> unmapped = TrinetraCommon.getStringList(scoreData, "unmapped_tests");
        Collections.sort(unmapped);

        StringBuilder sb = new StringBuilder();
        sb.append("# Compliance Narrative Report — ").append(session).append("\n\n");
        sb.append("| Field | Value |\n|-------|-------|\n");
        sb.append("| **Session** | ").append(session).append(" |\n");
        sb.append("| **Target** | ").append(target).append(" |\n");
        sb.append("| **Generated** | ").append(TrinetraCommon.nowIso()).append(" |\n");
        sb.append("| **Narrative Source** | ")
          .append(SOURCE_LLM.equals(source)
              ? "Gemini LLM (numbers validated against scorer output)"
              : fallbackReason == null ? "Template fallback" : fallbackReason)
          .append(" |\n");
        sb.append("| **LLM Attempts** | ").append(attempts).append(" |\n\n");
        sb.append("---\n\n");

        sb.append("## Framework Narratives\n\n");
        sb.append(body);
        sb.append("\n---\n\n");

        sb.append("## Unmapped Tests\n\n");
        if (unmapped.isEmpty()) {
            sb.append("All executed tests are present in the compliance manifest; nothing is unmapped.\n");
        } else {
            sb.append("The following tests were executed in this session but are not yet present in the ")
              .append("compliance manifest (config/compliance_manifest.json). They are **not** compliance failures — ")
              .append("they simply carry no framework mapping yet and are excluded from all percentages above:\n\n");
            for (String t : unmapped) sb.append("- ").append(t).append("\n");
            sb.append("\nInterpretation: mapping backlog only. Add these test IDs to the manifest to include them in future scores.\n");
        }
        sb.append("\n---\n\n");
        sb.append(SOURCE_LLM.equals(source)
            ? "_Generated by Trinetra Beta — narrative layer. Every numeric value in the narrative above was machine-validated against the deterministic compliance scorer output._\n"
            : "_Generated by Trinetra Beta — TEMPLATE-GENERATED narrative built directly from deterministic scorer data; no LLM content included._\n");
        return sb.toString();
    }
}
