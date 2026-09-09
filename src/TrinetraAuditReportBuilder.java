import java.nio.file.*;
import java.util.*;

/**
 * Final deliverable audit-report assembler (Prompt 17).
 *
 * Merges the three verified per-session data planes into the handover
 * artifact set:
 *   1. Brain-state execution record — tamper-evident, hash-chained
 *      normalized_results (device/vendor/test_id/verdict/timestamp).
 *   2. TrinetraComplianceScorer output — deterministic per-framework
 *      percentages, controls covered/gaps, pass/fail counts, unmapped tests.
 *   3. TrinetraNarrativeGenerator output — validated (or template-fallback)
 *      plain-language narrative built strictly from #2's numbers.
 *
 * Output tiers (both derived artifacts, like Prompts 15-16):
 *   - sessions/<name>/report_<FRAMEWORK>_<name>.md   one per framework
 *   - sessions/<name>/audit_report_<name>.md         combined appended report
 *
 * Hard rules:
 *   - NEVER writes to brain state, the normalized_results hash chain,
 *     or BRAIN_STATE_REQUIRED fields. Read-only against session state.
 *   - Executive-summary aggregates are computed deterministically in Java
 *     and explicitly labeled as derived, not scorer-native.
 *   - Provenance honesty: a template-fallback narrative carries its
 *     "TEMPLATE-GENERATED" label into the final report.
 *   - Frameworks with zero mapped tests are skipped (no file) and their
 *     absence is noted in the combined report rather than erroring.
 */
public class TrinetraAuditReportBuilder {

    /** Marker written by TrinetraNarrativeGenerator on fallback; used to
     *  detect provenance of an already-on-disk narrative. */
    public static final String TEMPLATE_MARKER = "TEMPLATE-GENERATED";

    // ── Entry point ──────────────────────────────────────────────────

    /**
     * Assemble both report tiers for a session. Generates the scorer JSON
     * and narrative markdown first when not already present for this
     * session.
     *
     * @return result metadata map {session_name, combined_path,
     *         framework_paths, skipped_frameworks, derived_aggregate_pct,
     *         narrative_source, chain_status} or null when the session has
     *         no readable brain-state record.
     */
    public static Map<String, Object> buildAuditReport(String sessionName) {
        return buildAuditReport(sessionName, null);
    }

    /**
     * Filtered variant — when frameworkFilter is non-null, only the selected
     * frameworks are scored and rendered; defaults to all via the no-filter
     * overload. Used by the React UI "user-selected benchmarks" path and the
     * bridge --frameworks param. Returns same metadata shape.
     */
    public static Map<String, Object> buildAuditReport(String sessionName, Set<String> frameworkFilter) {
        String sanitized = TrinetraCommon.sanitizeName(sessionName);

        Map<String, Object> brainState = TrinetraCommon.readJsonFile(
            TrinetraCommon.sessionBrainState(sanitized));
        if (brainState.isEmpty()) {
            TrinetraCommon.logError(
                "Cannot build audit report — brain state not found: "
                + TrinetraCommon.sessionBrainState(sanitized));
            return null;
        }

        // Rebuild on explicit export: file existence is not a freshness check.
        Path scorePath = TrinetraComplianceScorer.scoreAndWrite(sanitized, frameworkFilter);
        Map<String, Object> score = TrinetraCommon.readJsonFile(scorePath);

        // ── Plane 3: narrative (generate if absent) ──
        Path narrPath = TrinetraCommon.sessionDir(sanitized)
            .resolve("compliance_narrative_" + sanitized + ".md");
        String narrative;
        String narrativeSource;
        Map<String, Object> meta = TrinetraNarrativeGenerator.generateReport(sanitized, score);
        narrativeSource = TrinetraCommon.getString(meta, "source",
            TrinetraNarrativeGenerator.SOURCE_TEMPLATE);
        narrative = orEmpty(TrinetraCommon.readFileIfExists(narrPath));
        boolean templateMode =
            TrinetraNarrativeGenerator.SOURCE_TEMPLATE.equals(narrativeSource);

        // ── Plane 1: raw execution evidence ──
        List<Map<String, Object>> results =
            TrinetraSession.getActiveNormalizedResults(sanitized);

        // test_id -> entries (a test may run more than once / many devices)
        Map<String, List<Map<String, Object>>> evidenceByTest = new LinkedHashMap<>();
        for (Map<String, Object> e : results) {
            evidenceByTest
                .computeIfAbsent(TrinetraCommon.getString(e, "test_id", "?"),
                                 k -> new ArrayList<>())
                .add(e);
        }

        // framework -> ordered evidence rows {entry, controls}
        Map<String, List<Map<String, Object>>> evidenceByFramework =
            new LinkedHashMap<>();
        for (Map.Entry<String, List<Map<String, Object>>> t
                : evidenceByTest.entrySet()) {
            Map<String, List<String>> mappings =
                TrinetraCompliance.getControlMappings(t.getKey());
            for (Map.Entry<String, List<String>> fw : mappings.entrySet()) {
                for (Map<String, Object> entry : t.getValue()) {
                    Map<String, Object> row = TrinetraCommon.newMap();
                    row.put("entry", entry);
                    row.put("controls", fw.getValue());
                    evidenceByFramework
                        .computeIfAbsent(fw.getKey(), k -> new ArrayList<>())
                        .add(row);
                }
            }
        }

        // ── Narrative sections indexed by framework ──
        Map<String, String> narrativeSections =
            extractFrameworkSections(narrative, score);

        // Device details for hardware columns (serial, model, OS version)
        Map<String, Map<String, Object>> deviceDetails = TrinetraSession.getAllDeviceDetails(sanitized);

        // ── Plane 4: per-session script-output evidence bundle (JSON + MD) ──
        // Every stat_script / config-ingest execution appends its raw stdout/stderr
        // to sessions/<session>/evidence_<session>.json (+ .md transcript).
        // The sections below cite that bundle as the report's evidence.
        // Scope parity: removed devices are excluded here exactly as they are
        // from normalized_results above — historical chain retained, reports filtered.
        Set<String> removedDevices = TrinetraSession.getRemovedDevices(sanitized);
        List<Map<String, Object>> scriptEvidence = new ArrayList<>();
        for (Map<String, Object> se : TrinetraEvidence.load(sanitized)) {
            String did = TrinetraCommon.getString(se, "device_id",
                TrinetraCommon.getString(se, "target", ""));
            if (!removedDevices.contains(did)) scriptEvidence.add(se);
        }
        String evidenceJsonName = "evidence_" + sanitized + ".json";
        String evidenceMdName = "evidence_" + sanitized + ".md";

        // ── Tier 1: per-framework reports ──
        Map<String, Object> frameworks = TrinetraCommon.getMap(score, "frameworks");
        List<String> frameworkPaths = new ArrayList<>();
        List<String> skipped = new ArrayList<>();
        for (String fw : frameworks.keySet()) {
            List<Map<String, Object>> rows =
                evidenceByFramework.getOrDefault(fw, Collections.emptyList());
            if (rows.isEmpty()) {
                skipped.add(fw);
                continue;
            }
            Path p = TrinetraCommon.sessionDir(sanitized)
                .resolve("report_" + fw + "_" + sanitized + ".md");
            TrinetraCommon.atomicWriteFile(p,
                renderFrameworkReport(sanitized, fw, frameworks.get(fw),
                                       rows, narrativeSections.get(fw),
                                       templateMode, deviceDetails,
                                       scriptEvidence, evidenceJsonName, evidenceMdName));
            frameworkPaths.add(p.toString());
        }

        // ── Tier 2: combined appended audit report ──
        double aggregate = round1(meanPercentage(frameworks));
        TrinetraSession.ChainVerifyResult chain = TrinetraSession.verifyChain(sanitized);
        List<String> auditUuids = TrinetraAudit.listAuditUuids(sanitized);

        Path combinedPath = TrinetraCommon.sessionDir(sanitized)
            .resolve("audit_report_" + sanitized + ".md");
        TrinetraCommon.atomicWriteFile(combinedPath,
            renderCombinedReport(sanitized, score, frameworks,
                                  evidenceByFramework, narrativeSections,
                                  narrative, templateMode, aggregate,
                                  chain, auditUuids, skipped, deviceDetails,
                                  scriptEvidence, evidenceJsonName, evidenceMdName) + renderConfigurationReviews(score));

        Map<String, Object> out = TrinetraCommon.newMap();
        out.put("session_name", sanitized);
        out.put("combined_path", combinedPath.toString());
        out.put("framework_paths", frameworkPaths);
        out.put("skipped_frameworks", skipped);
        out.put("derived_aggregate_pct", aggregate);
        out.put("narrative_source", narrativeSource);
        out.put("chain_status", chain.toString());
        return out;
    }

    /**
     * Per-device report — single PDF per device as required by PS.
     * Filters evidence to one device_id; baseline and device_details are included.
     */
    public static Map<String, Object> buildDeviceReport(String sessionName, String deviceId, Set<String> frameworkFilter) {
        String sanitized = TrinetraCommon.sanitizeName(sessionName);
        String did = deviceId != null ? deviceId.trim() : "";
        if (did.isEmpty()) return null;

        Map<String, Object> brainState = TrinetraCommon.readJsonFile(
            TrinetraCommon.sessionBrainState(sanitized));
        if (brainState.isEmpty()) return null;

        // Device existence check
        Map<String, String> allVendors = TrinetraSession.getAllDeviceVendors(sanitized);
        SecurityBaseline baseline = TrinetraSession.getDeviceBaseline(sanitized, did);
        if (!allVendors.containsKey(did) && baseline == null) {
            // Also check normalized_results for device
            boolean found = false;
            for (Map<String, Object> e : TrinetraSession.getActiveNormalizedResults(sanitized)) {
                if (did.equals(TrinetraCommon.getString(e, "device_id", ""))) { found = true; break; }
            }
            if (!found) return null;
        }

        // Rebuild scorer artifacts (filtered by framework if requested)
        Path scorePath = TrinetraComplianceScorer.scoreAndWrite(sanitized, frameworkFilter);
        Map<String, Object> score = TrinetraCommon.readJsonFile(scorePath);

        Path narrPath = TrinetraCommon.sessionDir(sanitized)
            .resolve("compliance_narrative_" + sanitized + ".md");
        String narrative;
        String narrativeSource;
        Map<String, Object> meta = TrinetraNarrativeGenerator.generateReport(sanitized, score);
        narrativeSource = TrinetraCommon.getString(meta, "source",
            TrinetraNarrativeGenerator.SOURCE_TEMPLATE);
        narrative = orEmpty(TrinetraCommon.readFileIfExists(narrPath));
        boolean templateMode =
            TrinetraNarrativeGenerator.SOURCE_TEMPLATE.equals(narrativeSource);

        // Filtered evidence: only this device
        List<Map<String, Object>> results = new ArrayList<>();
        for (Map<String, Object> e : TrinetraSession.getActiveNormalizedResults(sanitized)) {
            if (did.equals(TrinetraCommon.getString(e, "device_id", ""))) results.add(e);
        }

        Map<String, List<Map<String, Object>>> evidenceByTest = new LinkedHashMap<>();
        for (Map<String, Object> e : results) {
            evidenceByTest.computeIfAbsent(TrinetraCommon.getString(e, "test_id", "?"), k -> new ArrayList<>()).add(e);
        }
        Map<String, List<Map<String, Object>>> evidenceByFramework = new LinkedHashMap<>();
        for (Map.Entry<String, List<Map<String, Object>>> t : evidenceByTest.entrySet()) {
            Map<String, List<String>> mappings = TrinetraCompliance.getControlMappings(t.getKey());
            for (Map.Entry<String, List<String>> fw : mappings.entrySet()) {
                if (frameworkFilter != null && !frameworkFilter.isEmpty()) {
                    String norm = fw.getKey().toLowerCase().replaceAll("[\\s\\-]", "_");
                    boolean match = false;
                    for (String f : frameworkFilter) {
                        if (norm.equals(f.toLowerCase().replaceAll("[\\s\\-]", "_"))) { match = true; break; }
                    }
                    if (!match) continue;
                }
                for (Map<String, Object> entry : t.getValue()) {
                    Map<String, Object> row = TrinetraCommon.newMap();
                    row.put("entry", entry);
                    row.put("controls", fw.getValue());
                    evidenceByFramework.computeIfAbsent(fw.getKey(), k -> new ArrayList<>()).add(row);
                }
            }
        }

        Map<String, String> narrativeSections = extractFrameworkSections(narrative, score);
        Map<String, Map<String, Object>> deviceDetails = TrinetraSession.getAllDeviceDetails(sanitized);
        // Include baseline map for report
        Map<String, SecurityBaseline> baselines = TrinetraSession.getAllDeviceBaselines(sanitized);

        Set<String> removed = TrinetraSession.getRemovedDevices(sanitized);
        List<Map<String, Object>> scriptEvidence = new ArrayList<>();
        for (Map<String, Object> se : TrinetraEvidence.load(sanitized)) {
            String sDid = TrinetraCommon.getString(se, "device_id", TrinetraCommon.getString(se, "target", ""));
            if (did.equals(sDid) && !removed.contains(sDid)) scriptEvidence.add(se);
        }
        String evidenceJsonName = "evidence_" + sanitized + ".json";
        String evidenceMdName = "evidence_" + sanitized + ".md";

        Map<String, Object> frameworks = TrinetraCommon.getMap(score, "frameworks");
        double aggregate = round1(meanPercentageFiltered(frameworks, evidenceByFramework));

        TrinetraSession.ChainVerifyResult chain = TrinetraSession.verifyChain(sanitized);
        List<String> auditUuids = TrinetraAudit.listAuditUuids(sanitized);

        String safeDid = TrinetraCommon.sanitizeName(did);
        Path devicePath = TrinetraCommon.sessionDir(sanitized)
            .resolve("audit_report_" + safeDid + "_" + sanitized + ".md");
        String deviceReport = renderDeviceReport(sanitized, did, score, frameworks,
            evidenceByFramework, narrativeSections, narrative, templateMode, aggregate,
            chain, auditUuids, deviceDetails.getOrDefault(did, Map.of()),
            baselines.get(did), scriptEvidence, evidenceJsonName, evidenceMdName, frameworkFilter);
        TrinetraCommon.atomicWriteFile(devicePath, deviceReport + renderConfigurationReviews(score) + renderBaselineSection(baselines.get(did)));

        Map<String, Object> out = TrinetraCommon.newMap();
        out.put("session_name", sanitized);
        out.put("device_id", did);
        out.put("combined_path", devicePath.toString());
        out.put("device_path", devicePath.toString());
        // Also generate per-framework per-device files for completeness
        List<String> frameworkPaths = new ArrayList<>();
        for (String fw : frameworks.keySet()) {
            List<Map<String, Object>> rows = evidenceByFramework.getOrDefault(fw, List.of());
            if (rows.isEmpty()) continue;
            Path p = TrinetraCommon.sessionDir(sanitized).resolve("report_" + fw + "_" + safeDid + "_" + sanitized + ".md");
            TrinetraCommon.atomicWriteFile(p,
                renderFrameworkReport(sanitized + " — " + did, fw, frameworks.get(fw), rows,
                    narrativeSections.get(fw), templateMode, deviceDetails, scriptEvidence, evidenceJsonName, evidenceMdName));
            frameworkPaths.add(p.toString());
        }
        out.put("framework_paths", frameworkPaths);
        out.put("derived_aggregate_pct", aggregate);
        out.put("narrative_source", narrativeSource);
        out.put("chain_status", chain.toString());
        out.put("baseline", baselines.get(did) != null ? baselines.get(did).toMap() : Map.of());
        return out;
    }

    private static String renderDeviceReport(String session, String deviceId,
                                             Map<String, Object> score,
                                             Map<String, Object> frameworks,
                                             Map<String, List<Map<String, Object>>> evidence,
                                             Map<String, String> sections,
                                             String fullNarrative,
                                             boolean templateMode,
                                             double aggregate,
                                             TrinetraSession.ChainVerifyResult chain,
                                             List<String> auditUuids,
                                             Map<String, Object> deviceDetail,
                                             SecurityBaseline baseline,
                                             List<Map<String, Object>> scriptEvidence,
                                             String evidenceJsonName,
                                             String evidenceMdName,
                                             Set<String> filter) {
        StringBuilder sb = new StringBuilder();
        sb.append("# Device Audit Report — ").append(deviceId).append(" (Session ").append(session).append(")\n\n");
        sb.append("| Field | Value |\n|-------|-------|\n");
        sb.append("| **Session** | ").append(cell(session)).append(" |\n");
        sb.append("| **Device ID** | ").append(cell(deviceId)).append(" |\n");
        sb.append("| **Vendor** | ").append(cell(TrinetraCommon.getString(deviceDetail, "vendor",
            baseline != null ? baseline.vendor : "unknown"))).append(" |\n");
        sb.append("| **Serial** | ").append(cell(TrinetraCommon.getString(deviceDetail, "serial_number", ""))).append(" |\n");
        sb.append("| **Hardware** | ").append(cell(TrinetraCommon.getString(deviceDetail, "hardware_model", ""))).append(" |\n");
        sb.append("| **OS Version** | ").append(cell(TrinetraCommon.getString(deviceDetail, "os_version", ""))).append(" |\n");
        if (baseline != null) {
            sb.append("| **Baseline Parser** | ").append(cell(baseline.parserVersion)).append(" |\n");
            sb.append("| **Baseline Vendor** | ").append(cell(baseline.vendor)).append(" |\n");
        }
        sb.append("| **Generated** | ").append(TrinetraCommon.nowIso()).append(" |\n");
        sb.append("| **Narrative provenance** | ").append(templateMode ? "TEMPLATE-GENERATED" : "Gemini LLM (number-validated)").append(" |\n");
        sb.append("| **Frameworks filtered** | ").append(filter == null || filter.isEmpty() ? "all" : String.join(", ", filter)).append(" |\n\n");

        sb.append("## Executive Summary (Device)\n\n");
        sb.append("**Device mapped-check pass rate (derived): ").append(aggregate).append("%** — per-device aggregate, not certification. Historical chain retained.\n\n");
        for (Map.Entry<String, Object> e : frameworks.entrySet()) {
            String fw = e.getKey();
            List<Map<String, Object>> rows = evidence.getOrDefault(fw, List.of());
            if (rows.isEmpty()) continue;
            Map<String, Object> fwScore = (Map<String, Object>) e.getValue();
            sb.append("### ").append(displayName(fw)).append("\n\n");
            sb.append("- Mapped-check pass rate (session): **").append(pctOf(fwScore)).append("%**\n");
            long pass = rows.stream().filter(r -> {
                Map<String, Object> entry = (Map<String, Object>) r.get("entry");
                return "pass".equalsIgnoreCase(TrinetraCommon.getString(entry, "normalized_result", ""));
            }).count();
            long fail = rows.stream().filter(r -> {
                Map<String, Object> entry = (Map<String, Object>) r.get("entry");
                return "fail".equalsIgnoreCase(TrinetraCommon.getString(entry, "normalized_result", ""));
            }).count();
            sb.append("- This device: ").append(pass).append(" pass / ").append(fail).append(" fail / ").append(rows.size()).append(" total mapped\n");
            String section = sections.get(fw);
            if (section != null && !section.isBlank()) sb.append("\n").append(section.strip()).append("\n");
            sb.append("\n**Evidence (device):**\n\n");
            sb.append("| Test ID | Verdict | Finding class | Severity | Controls | Evidence |\n");
            sb.append("|---------|---------|---------------|----------|----------|----------|\n");
            for (Map<String, Object> row : rows) {
                Map<String, Object> entry = (Map<String, Object>) row.get("entry");
                String tid = TrinetraCommon.getString(entry, "test_id", "?");
                String verdict = TrinetraCommon.getString(entry, "normalized_result", "?");
                String fc = TrinetraFindingClassification.classifyEntry(entry);
                String sev = resolveSeverity(tid, entry);
                sb.append("| ").append(cell(tid)).append(" | ").append(cell(verdict)).append(" | ").append(cell(fc)).append(" | ").append(cell(sev)).append(" | ").append(cell(joinList(row.get("controls")))).append(" | ").append(cell(String.join(" | ", evidenceLinesOf(entry)))).append(" |\n");
            }
            sb.append("\n").append(renderRemediationSection(rows, deviceDetail.isEmpty() ? Map.of() : Map.of(deviceId, deviceDetail))).append("\n");
        }
        sb.append("---\n\n");
        sb.append(renderScriptEvidenceSection(session, null, scriptEvidence, evidenceJsonName, evidenceMdName, false));
        sb.append("---\n\n## Appendix\n\n");
        sb.append("| Session | ").append(cell(session)).append(" |\n");
        sb.append("| Device | ").append(cell(deviceId)).append(" |\n");
        sb.append("| Chain | ").append(cell(chain.toString())).append(" |\n");
        sb.append("| Audit UUIDs | ").append(auditUuids.isEmpty() ? "_none_" : cell(String.join("<br>", auditUuids))).append(" |\n\n");
        sb.append(chain.intact ? "**Status: INTACT.**" : "**Status: BROKEN.**").append("\n");
        return sb.toString();
    }

    private static String renderBaselineSection(SecurityBaseline baseline) {
        if (baseline == null) return "\n## Baseline (vendor-neutral)\n\n_No baseline captured (legacy session — re-upload)._\n";
        StringBuilder sb = new StringBuilder("\n## Baseline (vendor-neutral, semantic)\n\n");
        sb.append("```json\n").append(TrinetraJson.prettyJson(baseline.toMap())).append("\n```\n");
        return sb.toString();
    }

    private static double meanPercentageFiltered(Map<String, Object> frameworks, Map<String, List<Map<String, Object>>> filtered) {
        if (filtered.isEmpty()) return 0.0;
        double sum = 0; int n = 0;
        for (String fw : filtered.keySet()) {
            Object o = frameworks.get(fw);
            if (o instanceof Map) { sum += pctOf((Map<?,?>)o); n++; }
        }
        // Device aggregate weighted by filtered rows: use simple mean of framework percentages that have device rows
        return n == 0 ? 0.0 : sum / n;
    }

    private static String renderConfigurationReviews(Map<String, Object> score) {
        StringBuilder text = new StringBuilder("\n## Configuration observations\n\n");
        text.append("Config limitation: Explicit text observations are not runtime findings or benchmark passes. Absence of a risky directive is not proof of safety. Historical verdicts are retained; re-upload to use current evaluation rules.\n\n");
        Object reviews = score.get("configuration_reviews");
        if (reviews instanceof List) for (Object value : (List<?>) reviews) {
            Map<?, ?> review = (Map<?, ?>) value;
            text.append("Config review: ").append(review.get("device_id")).append("; parser: ").append(review.get("parser")).append("; recorded: ").append(review.get("recorded_at")).append("\n\n");
            Object observations = review.get("observations");
            if (observations instanceof List) for (Object item : (List<?>) observations) {
                Map<?, ?> row = (Map<?, ?>) item;
                text.append("Config observation: ").append(row.get("id")).append(" — ").append(row.get("title"))
                    .append("; ").append(row.get("status")).append("; source lines ").append(row.get("line_numbers"))
                    .append(". ").append(row.get("next_step")).append("\n\n");
            }
        }
        return text.toString();
    }

    // ── Per-framework report ─────────────────────────────────────────

    private static String renderFrameworkReport(String session, String fw,
                                                Object fwScoreObj,
                                                List<Map<String, Object>> rows,
                                                String section,
                                                boolean templateMode,
                                                Map<String, Map<String, Object>> deviceDetails,
                                                List<Map<String, Object>> scriptEvidence,
                                                String evidenceJsonName,
                                                String evidenceMdName) {
        @SuppressWarnings("unchecked")
        Map<String, Object> fwScore =
            fwScoreObj instanceof Map ? (Map<String, Object>) fwScoreObj
                                      : TrinetraCommon.newMap();

        StringBuilder sb = new StringBuilder();
        sb.append("# ").append(displayName(fw))
          .append(" Compliance Report — ").append(session).append("\n\n");
        sb.append("| Field | Value |\n|-------|-------|\n");
        sb.append("| **Session** | ").append(session).append(" |\n");
        sb.append("| **Framework** | ").append(displayName(fw)).append(" |\n");
        sb.append("| **Generated** | ").append(TrinetraCommon.nowIso()).append(" |\n");
        sb.append("| **Narrative provenance** | ")
          .append(templateMode
              ? "TEMPLATE-GENERATED (deterministic fallback; no LLM content)"
              : "Gemini LLM (number-validated)")
          .append(" |\n\n");

        sb.append("## Compliance Score\n\n");
        sb.append("Mapped-check pass rate is not a compliance certification. Unresolved outcomes are not confirmed failures.\n\n");
        sb.append("- **Mapped-check pass rate: ")
          .append(pctOf(fwScore)).append("%**\n");
        sb.append("- Mapped tests passed: ").append(intOf(fwScore, "tests_passed"))
          .append("\n");
        sb.append("- Mapped tests failed: ").append(intOf(fwScore, "tests_failed"))
          .append("\n");
        sb.append("- Manual review: ").append(intOf(fwScore, "tests_manual_review"))
          .append("; errors: ").append(intOf(fwScore, "tests_errors"))
          .append("; not tested: ").append(intOf(fwScore, "tests_not_tested")).append("\n");
        sb.append("- Total mapped tests: ").append(intOf(fwScore, "total_tests_mapped"))
          .append("\n\n");

        sb.append("## Controls Covered\n\n");
        List<String> covered = strList(fwScore.get("controls_covered"));
        if (covered.isEmpty()) {
            sb.append("_None._\n\n");
        } else {
            for (String c : covered) sb.append("- ").append(c).append("\n");
            sb.append("\n");
        }

        sb.append("## Controls Not Covered (coverage gaps)\n\n");
        List<String> gaps = strList(fwScore.get("coverage_gaps"));
        if (gaps.isEmpty()) {
            sb.append("_None — every control in this framework's manifest scope ")
              .append("was exercised by at least one executed test._\n\n");
        } else {
            for (String g : gaps) sb.append("- ").append(g).append("\n");
            sb.append("\n");
        }

        sb.append("## Narrative Assessment\n\n");
        if (section != null && !section.isBlank()) {
            sb.append(section.strip()).append("\n\n");
        } else {
            sb.append("_No narrative section was available for this framework ")
              .append("in the generated compliance narrative._\n\n");
        }

        sb.append("## Test Evidence\n\n");
        sb.append("Finding classes: **confirmed risk** = insecure directive found; **verified pass** = secure directive found; **insufficient evidence** = a supported semantic check lacked decisive syntax; **unsupported check** = this control needs live, inventory, host, cloud-service, or other evidence not present in the upload. Vendor adapters currently cover Cisco, Juniper, FortiOS, PAN-OS, SONiC and AWS at different documented evidence depths; adapter availability is not production validation.\n\n");
        sb.append("| Device | Vendor | Serial | Hardware | OS Version | Ingestion | Test ID | Verdict | Finding class | Severity | Timestamp | Controls |\n");
        sb.append("|--------|--------|--------|----------|------------|-----------|---------|---------|---------------|----------|-----------|----------|\n");
        for (Map<String, Object> row : rows) {
            @SuppressWarnings("unchecked")
            Map<String, Object> e = (Map<String, Object>) row.get("entry");
            String did = TrinetraCommon.getString(e, "device_id", "?");
            String testId = TrinetraCommon.getString(e, "test_id", "?");
            String severity = resolveSeverity(testId, e);
            String fclass = TrinetraFindingClassification.classifyEntry(e);
            Map<String, Object> det = deviceDetails.getOrDefault(did, Collections.emptyMap());
            sb.append("| ").append(cell(did))
              .append(" | ").append(cell(TrinetraCommon.getString(e, "vendor", "?")))
              .append(" | ").append(cell(TrinetraCommon.getString(det, "serial_number", "")))
              .append(" | ").append(cell(TrinetraCommon.getString(det, "hardware_model", "")))
              .append(" | ").append(cell(TrinetraCommon.getString(det, "os_version", "")))
              .append(" | ").append(cell(TrinetraCommon.getString(e, "ingestion_method", "")))
              .append(" | ").append(cell(testId))
              .append(" | ").append(cell(TrinetraCommon.getString(e, "normalized_result", "?")))
              .append(" | ").append(cell(fclass))
              .append(" | ").append(cell(severity))
              .append(" | ").append(cell(TrinetraCommon.getString(e, "timestamp", "?")))
              .append(" | ").append(cell(joinList(row.get("controls"))))
              .append(" |\n");
        }
        sb.append("\n");
        sb.append(renderRemediationSection(rows, deviceDetails));
        sb.append("\n---\n\n");
        sb.append(renderScriptEvidenceSection(session, rows, scriptEvidence,
            evidenceJsonName, evidenceMdName, true));
        sb.append("_Derived artifact assembled from the session's tamper-evident ")
          .append("brain-state execution record, the deterministic compliance scorer ")
          .append("output, and the validated narrative layer. Not part of the hash ")
          .append("chain._\n");
        return sb.toString();
    }

    // ── Combined appended audit report ───────────────────────────────

    private static String renderCombinedReport(String session,
                                               Map<String, Object> score,
                                               Map<String, Object> frameworks,
                                               Map<String, List<Map<String, Object>>> evidence,
                                               Map<String, String> sections,
                                               String fullNarrative,
                                               boolean templateMode,
                                               double aggregate,
                                               TrinetraSession.ChainVerifyResult chain,
                                               List<String> auditUuids,
                                               List<String> skippedFw,
                                               Map<String, Map<String, Object>> deviceDetails,
                                               List<Map<String, Object>> scriptEvidence,
                                               String evidenceJsonName,
                                               String evidenceMdName) {
        String target = TrinetraCommon.getString(
            TrinetraSession.loadSession(session), "target", "unknown");

        StringBuilder sb = new StringBuilder();
        sb.append("# Combined Audit Report — ").append(session).append("\n\n");
        sb.append("Assessment scope excludes removed devices: ")
          .append(TrinetraSession.getRemovedDevices(session).size())
          .append(". Historical evidence and its chain remain retained; earlier exported reports are unchanged.\n\n");
        sb.append("| Field | Value |\n|-------|-------|\n");
        sb.append("| **Session** | ").append(session).append(" |\n");
        sb.append("| **Target** | ").append(cell(target)).append(" |\n");
        sb.append("| **Generated** | ").append(TrinetraCommon.nowIso()).append(" |\n");
        sb.append("| **Frameworks scored** | ").append(frameworks.size()).append(" |\n");
        sb.append("| **Narrative provenance** | ")
          .append(templateMode
              ? "TEMPLATE-GENERATED (deterministic fallback; no LLM content)"
              : "Gemini LLM (number-validated)")
          .append(" |\n\n");

        // ── Executive summary ──
        sb.append("## Executive Summary\n\n");
        int executed = intOf(score, "total_tests_executed");
        List<String> unmapped = strList(score.get("unmapped_tests"));
        int mappedExecutions = 0;
        int passedSum = 0;
        double minPct = Double.MAX_VALUE;
        double maxPct = Double.MIN_VALUE;
        for (Object o : frameworks.values()) {
            Map<String, Object> fw = (Map<String, Object>) o;
            mappedExecutions += intOf(fw, "total_tests_mapped");
            passedSum += intOf(fw, "tests_passed");
            double pct = pctOf(fw);
            minPct = Math.min(minPct, pct);
            maxPct = Math.max(maxPct, pct);
        }

        sb.append("**Average mapped-check pass rate (derived aggregate): ");
        if (frameworks.isEmpty()) {
            sb.append("N/A — no compliance-mapped frameworks were exercised");
        } else {
            sb.append(round1(aggregate)).append("% (not a compliance certification)");
        }
        sb.append(".**\n\n");
        sb.append("The figure above is a **derived aggregate computed deterministically ")
          .append("by the report builder as the unweighted mean of the per-framework ")
          .append("compliance_percentage values produced by TrinetraComplianceScorer")
          .append(frameworks.isEmpty() ? ""
              : " (" + rangeLabel(minPct, maxPct) + ")")
          .append(". It is NOT a scorer-native field and no LLM produced it.**\n\n");

        sb.append("- Tests executed (scorer-native total_tests_executed): ").append(executed).append("\n");
        sb.append("- Framework-mapped test executions (sum over frameworks; a test mapping ")
          .append("to several frameworks counts once per framework): ").append(mappedExecutions).append("\n");
        sb.append("- Mapped executions passed across all frameworks: ").append(passedSum).append("\n");
        sb.append("- Unmapped tests (mapping backlog, excluded from scores): ").append(unmapped.size()).append("\n\n");

        // ── Per-framework sections appended in sequence ──
        sb.append("---\n\n## Framework Reports\n\n");
        if (frameworks.isEmpty()) {
            sb.append("_Zero framework sections: no executed test mapped to any ")
              .append("framework in the compliance manifest._\n\n");
        }
        for (Map.Entry<String, Object> e : frameworks.entrySet()) {
            String fw = e.getKey();
            List<Map<String, Object>> rows =
                evidence.getOrDefault(fw, Collections.emptyList());
            sb.append("### ").append(displayName(fw)).append("\n\n");
            if (rows.isEmpty()) {
                sb.append("_Skipped: no executed tests map to this framework; no ")
                  .append("per-framework report file was generated._\n\n");
                continue;
            }
            Map<String, Object> fwScore = (Map<String, Object>) e.getValue();
            sb.append("- Mapped-check pass rate: **").append(pctOf(fwScore)).append("%**\n");
            sb.append("- Passed/failed/total mapped: ")
              .append(intOf(fwScore, "tests_passed")).append("/")
              .append(intOf(fwScore, "tests_failed")).append("/")
              .append(intOf(fwScore, "total_tests_mapped")).append("\n");
            sb.append("- Manual review/errors/not tested: ")
              .append(intOf(fwScore, "tests_manual_review")).append("/")
              .append(intOf(fwScore, "tests_errors")).append("/")
              .append(intOf(fwScore, "tests_not_tested")).append("\n");
            List<String> covered = strList(fwScore.get("controls_covered"));
            List<String> gaps = strList(fwScore.get("coverage_gaps"));
            sb.append("- Controls covered (").append(covered.size()).append("): ")
              .append(covered.isEmpty() ? "_none_" : String.join(", ", covered)).append("\n");
            sb.append("- Controls not covered (").append(gaps.size()).append("): ")
              .append(gaps.isEmpty() ? "_none_" : String.join(", ", gaps)).append("\n");
            sb.append("- Detail file: `report_").append(fw).append("_")
              .append(session).append(".md`\n\n");

            sb.append("**Narrative assessment")
              .append(templateMode ? " (template-generated)" : "")
              .append(":**\n\n");
            String section = sections.get(fw);
            sb.append(section != null && !section.isBlank()
                ? section.strip() + "\n\n"
                : "_No narrative section available for this framework._\n\n");

            sb.append("Test evidence (finding classes: confirmed risk / verified pass / insufficient evidence / unsupported check):\n\n");
            sb.append("| Device | Vendor | Serial | Hardware | OS Version | Ingestion | Test ID | Verdict | Finding class | Severity | Timestamp |\n");
            sb.append("|--------|--------|--------|----------|------------|-----------|---------|---------|---------------|----------|------------|\n");
            for (Map<String, Object> row : rows) {
                @SuppressWarnings("unchecked")
                Map<String, Object> entry = (Map<String, Object>) row.get("entry");
                String did2 = TrinetraCommon.getString(entry, "device_id", "?");
                String tid2 = TrinetraCommon.getString(entry, "test_id", "?");
                String sev2 = resolveSeverity(tid2, entry);
                String fc2 = TrinetraFindingClassification.classifyEntry(entry);
                Map<String, Object> det2 = deviceDetails.getOrDefault(did2, Collections.emptyMap());
                sb.append("| ").append(cell(did2))
                  .append(" | ").append(cell(TrinetraCommon.getString(entry, "vendor", "?")))
                  .append(" | ").append(cell(TrinetraCommon.getString(det2, "serial_number", "")))
                  .append(" | ").append(cell(TrinetraCommon.getString(det2, "hardware_model", "")))
                  .append(" | ").append(cell(TrinetraCommon.getString(det2, "os_version", "")))
                  .append(" | ").append(cell(TrinetraCommon.getString(entry, "ingestion_method", "")))
                  .append(" | ").append(cell(tid2))
                  .append(" | ").append(cell(TrinetraCommon.getString(entry, "normalized_result", "?")))
                  .append(" | ").append(cell(fc2))
                  .append(" | ").append(cell(sev2))
                  .append(" | ").append(cell(TrinetraCommon.getString(entry, "timestamp", "?")))
                  .append(" |\n");
            }
            sb.append("\n");
            sb.append(renderRemediationSection(rows));
            sb.append("\n");
        }
        if (!skippedFw.isEmpty()) {
            sb.append("Note: the following frameworks had zero mapped tests and no ")
              .append("per-framework report file: ")
              .append(String.join(", ", skippedFw)).append("\n\n");
        }

        // PS-required: CIS, NIST 800-53, ISO 27001, STIG — all four now have real manifest mappings.
        // PCI-DSS / SOC2 remain bonus/additional coverage.
        sb.append("> **Framework scope note:** *CIS, NIST 800-53, ISO 27001, and STIG are the PS-required frameworks. PCI-DSS and SOC2 are shown as **bonus/additional coverage** only and are not PS-required. STIG mappings sourced from DISA STIG Viewer — Cisco IOS Switch NDM STIG V2R5 / Juniper SRX SG NDM STIG V2R4 (Group IDs CISC-ND-xxxxxx / JUSX-ND-xxxxxx, see compliance_manifest.json `_STIG_source_note`). Partial real coverage — STIG coverage_gaps reflect applicability, not placeholder.*\n\n");

        // ── Unmapped tests ──
        sb.append("---\n\n## Unmapped Tests\n\n");
        if (unmapped.isEmpty()) {
            sb.append("All executed tests are present in the compliance manifest; ")
              .append("nothing is unmapped.\n\n");
        } else {
            sb.append("These tests were executed but carry no framework mapping yet. ")
              .append("They are **not** compliance failures — mapping backlog only.\n\n");
            for (String t : unmapped) sb.append("- ").append(t).append("\n");
            sb.append("\n");
        }

        // ── Script-output evidence (per-session JSON + MD bundle) ──
        sb.append("---\n\n");
        sb.append(renderScriptEvidenceSection(session, null, scriptEvidence,
            evidenceJsonName, evidenceMdName, false));

        // ── Appendix: raw execution metadata + tamper evidence ──
        sb.append("---\n\n## Appendix: Raw Execution Metadata\n\n");
        sb.append("| Field | Value |\n|-------|-------|\n");
        sb.append("| Session name | ").append(session).append(" |\n");
        sb.append("| Audit UUID(s) (trinetra_audit.db) | ")
          .append(auditUuids.isEmpty()
              ? "_none recorded_"
              : cell(String.join("<br>", auditUuids)))
          .append(" |\n");
        sb.append("| Generation timestamp | ").append(TrinetraCommon.nowIso()).append(" |\n\n");

        sb.append("### Tamper-evidence statement\n\n");
        sb.append("The underlying execution data for this report lives in the session's ")
          .append("hash-chained `normalized_results` log (SHA-256 linked, genesis-seeded). ")
          .append("Verification at report-generation time returned:\n\n");
        sb.append("```text\n").append(chain.toString()).append("\n```\n\n");
        String verdictLine = chain.intact
            ? "**Status: INTACT.** Every link verified; the delivered report asserts "
              + "the execution record has not been tampered with."
            : "**Status: BROKEN.** The delivered report MUST NOT be trusted as "
              + "evidence until the chain break above is investigated.";
        sb.append(verdictLine).append("\n\n");

        sb.append("This combined report and the per-framework files are DERIVED artifacts ")
          .append("(same class as the Prompt 15 scoring JSON and Prompt 16 narrative). They ")
          .append("are deliberately NOT part of `BRAIN_STATE_REQUIRED`, the normalized_results ")
          .append("array, or the hash chain.\n\n---\n\n");
        String provenanceFooter = templateMode
            ? "_Provenance: TEMPLATE-GENERATED narrative layer — the plain-language "
              + "sections were produced deterministically from scorer data with no "
              + "LLM content. All figures originate from TrinetraComplianceScorer._"
            : "_Provenance: Gemini LLM narrative layer; every numeric value machine-validated "
              + "against TrinetraComplianceScorer output. Aggregates computed in Java._";
        sb.append(provenanceFooter).append("\n");
        return sb.toString();
    }

    // ── Traceable remediation (review item 1c) ───────────────────────
    //
    // Policy: curated Cisco IOS CLI sequences (TrinetraAgr) are shown ONLY for
    // confirmed-risk rows, each paired with its exact source lines. Rationale:
    // a confirmed risk means an anchored insecure directive was matched with
    // comments/banners/negations excluded, so the fix is specific; it is still
    // gated by an explicit review warning because effective device state was
    // not proven live. All other classes keep generic cautious guidance so no
    // device-changing command is shown without triggering evidence.
    private static String renderRemediationSection(List<Map<String, Object>> rows) {
        return renderRemediationSection(rows, Map.of());
    }

    private static String renderRemediationSection(List<Map<String, Object>> rows, Map<String, Map<String, Object>> deviceDetails) {
        StringBuilder sb = new StringBuilder();
        sb.append("### Remediation (traceable, version-aware)\n\n");
        List<Map<String, Object>> confirmed = new ArrayList<>();
        for (Map<String, Object> row : rows) {
            Object entry = row.get("entry");
            if (entry instanceof Map
                && TrinetraFindingClassification.CONFIRMED_RISK.equals(
                    TrinetraFindingClassification.classifyEntry((Map<String, Object>) entry))) {
                confirmed.add(row);
            }
        }
        if (confirmed.isEmpty()) {
            sb.append("_No confirmed-risk findings in this section — no device-changing steps are shown. "
              + "Review generic guidance per row before any change._\n\n");
            return sb.toString();
        }
        // Deduplicate by test_id+device so re-uploaded history does not repeat steps.
        Set<String> seen = new LinkedHashSet<>();
        for (Map<String, Object> row : confirmed) {
            @SuppressWarnings("unchecked")
            Map<String, Object> e = (Map<String, Object>) row.get("entry");
            String tid = TrinetraCommon.getString(e, "test_id", "?");
            String did = TrinetraCommon.getString(e, "device_id", "?");
            String key = tid + "@" + did;
            if (!seen.add(key)) continue;
            Map<String, Object> det = deviceDetails.getOrDefault(did, Map.of());
            String vendor = TrinetraCommon.getString(det, "vendor", TrinetraCommon.getString(e, "vendor", ""));
            String osVer = TrinetraCommon.getString(det, "os_version", "");
            String curated = TrinetraAgr.getRemediation(tid, vendor, osVer);
            if (curated.isBlank()) curated = TrinetraAgr.getRemediation(tid);
            sb.append("Remediation: ").append(tid).append(" on ").append(did)
              .append(" — confirmed risk. [").append(vendor.isEmpty() ? "generic" : vendor).append(osVer.isEmpty() ? "" : " " + osVer).append("]\n\n");
            List<String> lines = evidenceLinesOf(e);
            if (!lines.isEmpty()) {
                sb.append("Triggering source lines: `");
                sb.append(String.join(" | ", lines).replace("|", "\\|"));
                sb.append("`\n\n");
            } else {
                sb.append("Triggering source lines: recorded in `evidence_*.json` for this test/device.\n\n");
            }
            if (!curated.isBlank()) {
                sb.append("Review-required guidance (confirm model, release, scope, backup, rollback, and post-change verification): ")
                  .append(curated).append("\n\n");
            } else {
                sb.append("No curated CLI sequence for this check — use the applicable vendor hardening guide with backup/rollback and post-change verification. "
                  + "Cortex does not validate or execute remediation commands.\n\n");
            }
        }
        return sb.toString();
    }

    private static List<String> evidenceLinesOf(Map<String, Object> entry) {
        List<String> out = new ArrayList<>();
        Object v = entry.get("evidence_lines");
        if (v instanceof List) {
            for (Object o : (List<?>) v) {
                if (o != null && !String.valueOf(o).isBlank()) out.add(String.valueOf(o));
                if (out.size() >= 5) break;
            }
        }
        return out;
    }

    // ── Script-output evidence section (shared) ──────────────────────

    /**
     * Render the per-session script-output evidence bundle as report markdown.
     *
     * @param rows when non-null (per-framework path), only evidence whose
     *             test_id appears in those rows is shown; when null (combined
     *             path) the full bundle is shown.
     * @param filtered true trims long outputs to a snippet per entry (framework
     *                 reports stay readable); false shows fuller outputs.
     */
    private static String renderScriptEvidenceSection(String session,
                                                      List<Map<String, Object>> rows,
                                                      List<Map<String, Object>> scriptEvidence,
                                                      String evidenceJsonName,
                                                      String evidenceMdName,
                                                      boolean filtered) {
        StringBuilder sb = new StringBuilder();
        sb.append("## Script Output Evidence\n\n");
        sb.append("Raw tool outputs backing every verdict above. Full machine-readable bundle: ")
          .append("`").append(evidenceJsonName).append("`; readable transcript: `")
          .append(evidenceMdName).append("` (both in `sessions/").append(session).append("/`).\n\n");
        if (scriptEvidence == null || scriptEvidence.isEmpty()) {
            sb.append("_No script output recorded yet. Run a stat check (`trinetra -stat run`) or upload a config — each execution appends its stdout/stderr to the evidence bundle._\n\n");
            return sb.toString();
        }
        Set<String> wanted = null;
        Set<String> wantedDevices = null;
        if (rows != null) {
            wanted = new HashSet<>();
            wantedDevices = new HashSet<>();
            for (Map<String, Object> row : rows) {
                Object entry = row.get("entry");
                if (entry instanceof Map) {
                    String tid = TrinetraCommon.getString(entry, "test_id", "");
                    if (!tid.isBlank()) wanted.add(tid);
                    String did = TrinetraCommon.getString(entry, "device_id", "");
                    if (!did.isBlank()) wantedDevices.add(did);
                }
            }
        }
        List<Map<String, Object>> shown = new ArrayList<>();
        for (Map<String, Object> e : scriptEvidence) {
            String tid = TrinetraCommon.getString(e, "test_id", "?");
            String did = TrinetraCommon.getString(e, "device_id",
                TrinetraCommon.getString(e, "target", ""));
            if (wanted != null && !wanted.contains(tid)) continue;
            if (wantedDevices != null && !wantedDevices.contains(did)) continue;
            shown.add(e);
        }
        if (shown.isEmpty()) {
            sb.append("_This framework has no script executions in the evidence bundle yet._\n\n");
            return sb.toString();
        }
        sb.append("Script evidence: ").append(shown.size()).append(" execution(s)")
          .append(filtered ? " relevant to this framework" : " in this session").append(".\n\n");
        int limit = filtered ? 12 : 60;
        int n = 0;
        for (Map<String, Object> e : shown) {
            if (n >= limit) {
                sb.append("_Showing ").append(limit).append(" of ").append(shown.size())
                  .append(" entries here; see `").append(evidenceJsonName).append("` / `")
                  .append(evidenceMdName).append("` for the complete bundle._\n\n");
                break;
            }
            n++;
            String tid = TrinetraCommon.getString(e, "test_id", "?");
            String verdict = TrinetraCommon.getString(e, "verdict", "?");
            String device = TrinetraCommon.getString(e, "device_id",
                TrinetraCommon.getString(e, "target", "?"));
            sb.append("Script evidence: ").append(tid).append(" on ").append(device)
              .append(" — ").append(verdict)
              .append(" [").append(TrinetraCommon.getString(e, "source", "")).append("]\n\n");
            String stdout = TrinetraCommon.getString(e, "stdout",
                TrinetraCommon.getString(e, "raw_output", ""));
            String stderr = TrinetraCommon.getString(e, "stderr", "");
            int snippetLen = filtered ? 1500 : 4000;
            sb.append("```text\n");
            if (stdout.isBlank()) {
                sb.append("(no stdout captured)\n");
            } else if (stdout.length() > snippetLen) {
                sb.append(stdout, 0, snippetLen)
                  .append("\n...[truncated, see ").append(evidenceJsonName).append("]...");
            } else {
                sb.append(stdout);
            }
            sb.append("\n```\n\n");
            if (!stderr.isBlank()) {
                sb.append("_stderr:_ `").append(cell(stderr.length() > 300
                    ? stderr.substring(0, 300) + "..." : stderr)).append("`\n\n");
            }
        }
        return sb.toString();
    }

    // ── Narrative section extraction ─────────────────────────────────

    /**
     * Split the narrative markdown into per-framework sections keyed by
     * the scorer's framework names. Matching normalizes away case and
     * separators so "NIST_800-53" also matches "### NIST 800-53".
     */
    private static Map<String, String> extractFrameworkSections(
            String narrative, Map<String, Object> score) {
        Map<String, String> out = new LinkedHashMap<>();
        if (narrative == null || narrative.isBlank()) return out;

        String body = narrative;
        int start = body.indexOf("## Framework Narratives");
        if (start >= 0) {
            body = body.substring(start + "## Framework Narratives".length());
            int end = body.indexOf("\n---");
            if (end >= 0) body = body.substring(0, end);
        }

        // Split into "### heading" blocks
        LinkedHashMap<String, String> blocks = new LinkedHashMap<>();
        String currentHeading = null;
        StringBuilder current = new StringBuilder();
        for (String line : body.split("\n", -1)) {
            if (line.startsWith("### ")) {
                if (currentHeading != null) blocks.put(currentHeading, current.toString());
                currentHeading = line.substring(4).trim();
                current = new StringBuilder();
            } else if (currentHeading != null) {
                current.append(line).append('\n');
            }
        }
        if (currentHeading != null) blocks.put(currentHeading, current.toString());

        Set<String> seen = new HashSet<>();
        for (Map.Entry<String, String> b : blocks.entrySet()) {
            String key = normalize(b.getKey());
            if (!seen.add(key)) continue;
            out.put(key, b.getValue());
        }

        // Re-key onto the scorer's exact framework names
        Map<String, String> rekeyed = new LinkedHashMap<>();
        for (String fw : TrinetraCommon.getMap(score, "frameworks").keySet()) {
            String section = out.get(normalize(fw));
            if (section != null) rekeyed.put(fw, section);
        }
        return rekeyed;
    }

    private static String normalize(String s) {
        return s == null ? "" : s.toLowerCase().replaceAll("[^a-z0-9]", "");
    }

    // ── Small helpers ────────────────────────────────────────────────

    /** Deterministic Java-side mean of scorer-native compliance_percentage values. */
    static double meanPercentage(Map<String, Object> frameworks) {
        if (frameworks.isEmpty()) return 0.0;
        double sum = 0;
        for (Object o : frameworks.values()) {
            sum += o instanceof Map ? pctOf((Map<?, ?>) o) : 0.0;
        }
        return sum / frameworks.size();
    }

    static double round1(double v) {
        return Math.round(v * 10.0) / 10.0;
    }

    private static double pctOf(Map<?, ?> m) {
        Object v = m.get("compliance_percentage");
        return v instanceof Number ? ((Number) v).doubleValue() : 0.0;
    }

    private static int intOf(Map<?, ?> m, String key) {
        Object v = m.get(key);
        if (v instanceof Number) return ((Number) v).intValue();
        try { return Integer.parseInt(String.valueOf(v)); }
        catch (Exception e) { return 0; }
    }

    private static List<String> strList(Object v) {
        List<String> out = new ArrayList<>();
        if (v instanceof List) {
            for (Object o : (List<?>) v) out.add(String.valueOf(o));
        }
        return out;
    }

    private static String joinList(Object v) {
        return String.join(", ", strList(v));
    }

    private static String resolveSeverity(String testId, Map<String, Object> entry) {
        // Prefer entry's stored severity if present, else lookup via static_map/decision_engine
        String sev = TrinetraCommon.getString(entry, "default_severity", "");
        if (!sev.isBlank()) return sev.toLowerCase();
        sev = TrinetraCommon.getString(entry, "severity", "");
        if (!sev.isBlank()) return sev.toLowerCase();
        TrinetraStat.TestDefinition def = TrinetraStat.getTestDefinition(testId);
        if (def != null && def.defaultSeverity != null && !def.defaultSeverity.isBlank()) {
            return def.defaultSeverity.toLowerCase();
        }
        return "medium";
    }

    private static String displayName(String fw) {
        if (fw == null) return "";
        // Explicit cases for known frameworks, generic title-casing fallback for any new manifest key
        return switch (fw) {
            case "ISO27001" -> "ISO 27001";
            case "NIST_800-53" -> "NIST 800-53";
            case "PCI-DSS" -> "PCI DSS";
            case "SOC2" -> "SOC 2";
            case "STIG" -> "STIG";
            default -> {
                // Generic: replace underscores/hyphens with spaces, Title Case words
                String spaced = fw.replace("_", " ").replace("-", " ").trim();
                if (spaced.isEmpty()) yield fw;
                String[] parts = spaced.split("\\s+");
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < parts.length; i++) {
                    if (i > 0) sb.append(' ');
                    String p = parts[i];
                    if (p.equalsIgnoreCase("stig") || p.equalsIgnoreCase("cis") || p.equalsIgnoreCase("iso") || p.equalsIgnoreCase("nist") || p.equalsIgnoreCase("pci") || p.equalsIgnoreCase("soc2")) {
                        sb.append(p.toUpperCase());
                    } else {
                        sb.append(Character.toUpperCase(p.charAt(0))).append(p.substring(1).toLowerCase());
                    }
                }
                yield sb.toString();
            }
        };
    }

    private static String rangeLabel(double min, double max) {
        return "framework range " + round1(min) + "%\u2013" + round1(max) + "%";
    }

    private static String cell(String s) {
        return s == null ? "" : s.replace("|", "\\|").replace("\n", " ");
    }

    private static String orEmpty(String s) {
        return s == null ? "" : s;
    }
}
