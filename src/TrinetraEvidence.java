import java.nio.file.*;
import java.util.*;

/**
 * Per-session script-output evidence store.
 *
 * Every stat_script / config-ingest execution appends one entry here, in
 * addition to the existing session JSON findings[] and the hash-chained
 * normalized_results[]. The two files below are the human- and
 * machine-readable evidence bundle referenced by the audit report:
 *
 *   sessions/&lt;session&gt;/evidence_&lt;session&gt;.json  — full structured outputs
 *   sessions/&lt;session&gt;/evidence_&lt;session&gt;.md    — readable transcript
 *
 * Entry shape (JSON):
 *   {evidence_id, recorded_at, source, device_id, vendor, test_id,
 *    test_name, verdict, severity, exit_code, script, stdout, stderr,
 *    raw_output, finding_id}
 *
 * Thread-safety: all read-modify-write cycles go through
 * TrinetraSession.withSessionStateLock (same family as brain-state writes)
 * so parallel stat runs cannot lose evidence entries.
 */
public class TrinetraEvidence {

    public static final int MAX_OUTPUT_CHARS = 20000;

    public static Path evidenceJsonPath(String session) {
        String s = TrinetraCommon.sanitizeName(session);
        return TrinetraCommon.sessionDir(s).resolve("evidence_" + s + ".json");
    }

    public static Path evidenceMdPath(String session) {
        String s = TrinetraCommon.sanitizeName(session);
        return TrinetraCommon.sessionDir(s).resolve("evidence_" + s + ".md");
    }

    /** Generic append — caller builds the entry map; I/O is lock-guarded. */
    public static boolean record(Map<String, Object> entry, String sessionName) {
        if (entry == null || sessionName == null) return false;
        String sanitized = TrinetraCommon.sanitizeName(sessionName);
        Boolean ok = TrinetraSession.withSessionStateLock(sanitized, () -> {
            Path jsonPath = evidenceJsonPath(sanitized);
            Map<String, Object> doc = TrinetraCommon.readJsonFile(jsonPath);
            List<Object> evidence;
            Object existing = doc.get("evidence");
            if (existing instanceof List) {
                evidence = new ArrayList<>((List<?>) existing);
            } else {
                evidence = new ArrayList<>();
            }
            Map<String, Object> rec = new LinkedHashMap<>();
            rec.put("evidence_id", entry.getOrDefault("evidence_id", UUID.randomUUID().toString()));
            rec.put("recorded_at", entry.getOrDefault("recorded_at", TrinetraCommon.nowIso()));
            rec.put("source", entry.getOrDefault("source", "stat_script"));
            rec.put("device_id", entry.getOrDefault("device_id", entry.getOrDefault("target", "")));
            rec.put("target", entry.getOrDefault("target", entry.getOrDefault("device_id", "")));
            rec.put("vendor", entry.getOrDefault("vendor", ""));
            rec.put("test_id", entry.getOrDefault("test_id", entry.getOrDefault("v_code", entry.getOrDefault("test_code", "?"))));
            rec.put("test_name", entry.getOrDefault("test_name", entry.getOrDefault("v_name", "")));
            rec.put("verdict", entry.getOrDefault("verdict", entry.getOrDefault("normalized_result", "unknown")));
            rec.put("severity", entry.getOrDefault("severity", entry.getOrDefault("default_severity", "")));
            rec.put("exit_code", entry.getOrDefault("exit_code", 0));
            rec.put("script", entry.getOrDefault("script", ""));
            rec.put("ingestion_method", entry.getOrDefault("ingestion_method", ""));
            rec.put("stdout", cap(String.valueOf(entry.getOrDefault("stdout", entry.getOrDefault("raw_output", "")))));
            rec.put("stderr", cap(String.valueOf(entry.getOrDefault("stderr", entry.getOrDefault("raw_stderr", "")))));
            rec.put("raw_output", cap(String.valueOf(entry.getOrDefault("raw_output", entry.getOrDefault("stdout", "")))));
            if (entry.containsKey("finding_id")) rec.put("finding_id", entry.get("finding_id"));
            if (entry.containsKey("verdict_detail")) rec.put("verdict_detail", entry.get("verdict_detail"));
            evidence.add(rec);

            Map<String, Object> out = new LinkedHashMap<>();
            out.put("session_name", sanitized);
            out.put("last_updated", TrinetraCommon.nowIso());
            out.put("evidence_count", evidence.size());
            out.put("evidence", evidence);
            TrinetraCommon.writeJsonFile(jsonPath, out);
            // Regenerate readable transcript from the same canonical list
            // so JSON and MD can never diverge.
            TrinetraCommon.atomicWriteFile(evidenceMdPath(sanitized), renderMarkdown(sanitized, evidence));
            return true;
        });
        return Boolean.TRUE.equals(ok);
    }

    /** Convenience for TrinetraStat.statRun findings. */
    public static boolean recordStatEvidence(String sessionName, Map<String, Object> finding,
                                             String vendor, String deviceId) {
        if (finding == null) return false;
        Map<String, Object> e = new LinkedHashMap<>(finding);
        e.put("source", "stat_script");
        e.put("device_id", deviceId != null ? deviceId : TrinetraCommon.getString(finding, "target", ""));
        e.put("target", TrinetraCommon.getString(finding, "target", deviceId != null ? deviceId : ""));
        e.put("vendor", vendor != null ? vendor : TrinetraCommon.getString(finding, "vendor", ""));
        e.put("test_id", TrinetraCommon.getString(finding, "v_code", TrinetraCommon.getString(finding, "test_code", "?")));
        e.put("test_name", TrinetraCommon.getString(finding, "v_name", ""));
        e.put("verdict", TrinetraCommon.getString(finding, "verdict", "unknown"));
        e.put("severity", TrinetraCommon.getString(finding, "default_severity", ""));
        e.putIfAbsent("evidence_id", UUID.randomUUID().toString());
        e.putIfAbsent("recorded_at", TrinetraCommon.nowIso());
        return record(e, sessionName);
    }

    /** Convenience for TrinetraConfigIngestor findings. */
    public static boolean recordConfigEvidence(String sessionName, Map<String, Object> finding) {
        if (finding == null) return false;
        Map<String, Object> e = new LinkedHashMap<>(finding);
        e.put("source", "config_ingest");
        // The uploaded configuration remains available as a protected session
        // artifact. Evidence bundles and reports receive only bounded, redacted
        // trigger lines so credentials are not duplicated into export surfaces.
        List<String> safeLines = new ArrayList<>();
        Object lines = finding.get("evidence_lines");
        if (lines instanceof List) {
            for (Object line : (List<?>) lines) {
                if (line != null) safeLines.add(SecurityBaseline.sanitizeEvidence(String.valueOf(line)));
                if (safeLines.size() >= 10) break;
            }
        }
        String reportOutput = safeLines.isEmpty()
            ? "Static configuration evaluated; raw configuration excluded from the exportable evidence bundle."
            : String.join("\n", safeLines);
        e.put("stdout", reportOutput);
        e.put("stderr", "");
        e.put("raw_output", reportOutput);
        e.putIfAbsent("evidence_id", UUID.randomUUID().toString());
        e.putIfAbsent("recorded_at", TrinetraCommon.nowIso());
        return record(e, sessionName);
    }

    @SuppressWarnings("unchecked")
    public static List<Map<String, Object>> load(String sessionName) {
        String sanitized = TrinetraCommon.sanitizeName(sessionName == null ? "" : sessionName);
        Map<String, Object> doc = TrinetraCommon.readJsonFile(evidenceJsonPath(sanitized));
        Object ev = doc.get("evidence");
        List<Map<String, Object>> out = new ArrayList<>();
        if (ev instanceof List) {
            for (Object o : (List<?>) ev) {
                if (o instanceof Map) out.add((Map<String, Object>) o);
            }
        }
        return out;
    }

    public static int count(String sessionName) {
        return load(sessionName).size();
    }

    private static String cap(String s) {
        if (s == null || "null".equals(s)) return "";
        if (s.length() <= MAX_OUTPUT_CHARS) return s;
        return s.substring(0, MAX_OUTPUT_CHARS) + "\n...[truncated " + (s.length() - MAX_OUTPUT_CHARS) + " chars]...";
    }

    /** Render the per-session readable transcript. Public so tests/reports reuse it. */
    public static String renderMarkdown(String sessionName, List<Object> evidence) {
        String sanitized = TrinetraCommon.sanitizeName(sessionName);
        StringBuilder sb = new StringBuilder();
        sb.append("# Script Output Evidence — ").append(sanitized).append("\n\n");
        sb.append("Machine-readable source: `evidence_").append(sanitized).append(".json`. ");
        sb.append("Each section below is one script execution and is cited as evidence in ");
        sb.append("`audit_report_").append(sanitized).append(".md` and the per-framework reports.\n\n");
        sb.append("| Field | Value |\n|-------|-------|\n");
        sb.append("| **Session** | ").append(sanitized).append(" |\n");
        sb.append("| **Generated** | ").append(TrinetraCommon.nowIso()).append(" |\n");
        sb.append("| **Evidence entries** | ").append(evidence.size()).append(" |\n\n");
        if (evidence.isEmpty()) {
            sb.append("_No script output recorded yet. Run a stat check or upload a config._\n");
            return sb.toString();
        }
        int n = 0;
        for (Object o : evidence) {
            if (!(o instanceof Map)) continue;
            @SuppressWarnings("unchecked")
            Map<String, Object> e = (Map<String, Object>) o;
            n++;
            String testId = str(e, "test_id", "?");
            String verdict = str(e, "verdict", "?");
            String device = str(e, "device_id", str(e, "target", "?"));
            sb.append("---\n\n## ").append(n).append(". ").append(testId)
              .append(" — ").append(verdict).append(" (").append(device).append(")\n\n");
            sb.append("- **Evidence ID:** `").append(str(e, "evidence_id", "")).append("`\n");
            sb.append("- **Recorded:** ").append(str(e, "recorded_at", "")).append("\n");
            sb.append("- **Source:** ").append(str(e, "source", "")).append("\n");
            sb.append("- **Device:** ").append(device).append("\n");
            sb.append("- **Vendor:** ").append(str(e, "vendor", "")).append("\n");
            sb.append("- **Test:** ").append(testId).append(" — ").append(str(e, "test_name", "")).append("\n");
            sb.append("- **Verdict:** ").append(verdict).append("\n");
            sb.append("- **Severity:** ").append(str(e, "severity", "")).append("\n");
            sb.append("- **Exit code:** ").append(str(e, "exit_code", "")).append("\n");
            sb.append("- **Script:** `").append(str(e, "script", "")).append("`\n");
            Object vd = e.get("verdict_detail");
            if (vd != null && !String.valueOf(vd).isBlank())
                sb.append("- **Detail:** ").append(String.valueOf(vd).replace("\n", " ")).append("\n");
            sb.append("\n### STDOUT\n\n```text\n");
            sb.append(orEmpty(e.get("stdout"))).append("\n```\n\n");
            String stderr = orEmpty(e.get("stderr"));
            if (!stderr.isBlank()) {
                sb.append("### STDERR\n\n```text\n").append(stderr).append("\n```\n\n");
            }
        }
        return sb.toString();
    }

    private static String orEmpty(Object v) {
        if (v == null) return "";
        String s = String.valueOf(v);
        return "null".equals(s) ? "" : s;
    }

    private static String str(Map<String, Object> m, String key, String def) {
        Object v = m.get(key);
        if (v == null) return def;
        String s = String.valueOf(v);
        return "null".equals(s) ? def : s;
    }
}
