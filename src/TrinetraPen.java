import java.io.*;
import java.nio.file.*;
import java.util.*;

/**
 * Pentest execution layer.
 * Dispatches V-XXX.sh scripts via HexStrike API.
 * Scripts now append findings to session JSON directly.
 */
public class TrinetraPen {

    /**
     * Run a V-code script against a target.
     * Script contract: bash V-XXX.sh <SESSION> <TARGET>
     * Scripts call HexStrike API and write findings to session JSON.
     * This method reads back the latest finding after execution.
     */
    public static Map<String, Object> run(String vCode, String sessionName, String target) {
        String sanitizedSession = TrinetraCommon.sanitizeName(sessionName);
        vCode = vCode.toUpperCase();

        // Duplicate guardrail: warn if V-code already run in this session
        Map<String, Object> brainState = TrinetraCommon.readJsonFile(
            TrinetraCommon.sessionBrainState(sanitizedSession));
        Object alreadyRun = brainState.get("already_run_v_codes");
        if (alreadyRun instanceof java.util.List) {
            java.util.List<?> runList = (java.util.List<?>) alreadyRun;
            if (runList.contains(vCode)) {
                TrinetraCommon.logWarn("V-code " + vCode + " already run in session " + sanitizedSession + " — re-running");
            }
        }

        // Resolve script: hex_scripts/V-XXX.sh
        Path scriptPath = TrinetraCommon.HEX_SCRIPTS_DIR.resolve(vCode + ".sh");
        if (!Files.exists(scriptPath)) {
            TrinetraCommon.logError("Script not found: " + scriptPath);
            return buildFailureFinding(vCode, target, "Script not found: " + vCode + ".sh");
        }

        // Ensure session exists
        Map<String, Object> session = TrinetraSession.loadSession(sanitizedSession);
        if (session == null) {
            TrinetraCommon.logInfo("Auto-creating session: " + sanitizedSession);
            session = TrinetraSession.createSession(sanitizedSession, target);
            if (session == null) {
                return buildFailureFinding(vCode, target, "Failed to create session: " + sanitizedSession);
            }
        }

        // Count existing findings before run (to detect new entry)
        int beforeCount = countFindings(sanitizedSession);

        TrinetraCommon.logInfo("Running " + vCode + " against " + target);
        TrinetraCommon.sessionLog(sanitizedSession, vCode, "START " + vCode + " against " + target);

        // Execute: bash V-XXX.sh <SESSION> <TARGET>
        String[] result = TrinetraCommon.execCommand(120, "bash", scriptPath.toString(), sanitizedSession, target);
        String stdout = result[0];
        String stderr = result[1];
        int exitCode;
        try { exitCode = Integer.parseInt(result[2]); } catch (Exception e) { exitCode = -1; }

        if (exitCode != 0) {
            TrinetraCommon.logWarn(vCode + " exited with code " + exitCode);
            TrinetraCommon.sessionLog(sanitizedSession, vCode, "EXIT_CODE=" + exitCode);
            if (!stderr.isEmpty()) TrinetraCommon.logWarn("stderr: " + truncate(stderr, 500));
        }

        // Read back the latest finding from session JSON
        // (scripts append their own findings via HexStrike API)
        Map<String, Object> latestFinding = getLatestFinding(sanitizedSession, beforeCount);

        if (latestFinding != null) {
            String status = TrinetraCommon.getString(latestFinding, "success", "false");
            TrinetraCommon.logInfo("Finding recorded: " + vCode + " (success=" + status + ")");
            TrinetraCommon.sessionLog(sanitizedSession, vCode, "DONE success=" + status);
            return latestFinding;
        }

        // Script ran but no finding was appended — build a minimal record
        TrinetraCommon.logWarn(vCode + " produced no finding in session JSON");
        Map<String, Object> finding = buildFailureFinding(vCode, target,
            "Script executed (exit=" + exitCode + ") but no finding appended to session JSON");
        finding.put("exit_code", exitCode);
        finding.put("raw_output", stdout);
        finding.put("raw_stderr", stderr);
        return finding;
    }

    /**
     * Get the latest finding from session JSON, starting search after beforeCount entries.
     */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> getLatestFinding(String sessionName, int beforeCount) {
        Path jsonPath = TrinetraCommon.sessionJson(sessionName);
        Map<String, Object> session = TrinetraCommon.readJsonFile(jsonPath);
        if (session.isEmpty()) return null;

        Object findingsObj = session.get("findings");
        if (!(findingsObj instanceof List)) return null;

        List<Object> findings = (List<Object>) findingsObj;
        if (findings.size() > beforeCount) {
            Object latest = findings.get(findings.size() - 1);
            if (latest instanceof Map) return (Map<String, Object>) latest;
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private static int countFindings(String sessionName) {
        Path jsonPath = TrinetraCommon.sessionJson(sessionName);
        Map<String, Object> session = TrinetraCommon.readJsonFile(jsonPath);
        if (session.isEmpty()) return 0;
        Object f = session.get("findings");
        if (f instanceof List) return ((List<?>) f).size();
        return 0;
    }

    private static Map<String, Object> buildFailureFinding(String vCode, String target, String error) {
        Map<String, Object> finding = TrinetraCommon.newMap();
        finding.put("finding_id", UUID.randomUUID().toString());
        finding.put("v_code", vCode);
        finding.put("v_name", vCode);
        finding.put("target", target);
        finding.put("script", "hex_scripts/" + vCode + ".sh");
        finding.put("started_at", TrinetraCommon.nowIso());
        finding.put("ended_at", TrinetraCommon.nowIso());
        finding.put("exit_code", -1);
        finding.put("success", false);
        finding.put("status", "failed");
        finding.put("stdout", error);
        finding.put("stderr", error);
        finding.put("raw_output", error);
        finding.put("raw_stderr", error);
        finding.put("summary", null);
        finding.put("summary_status", "captured_but_unsummarized");
        finding.put("summary_error", error);
        finding.put("artifacts", TrinetraCommon.newList());
        finding.put("tags", TrinetraCommon.newList());
        return finding;
    }

    /**
     * List all available V-codes by scanning hex_scripts/V-*.sh
     */
    public static List<String> listVCodes() {
        List<String> codes = new ArrayList<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(TrinetraCommon.HEX_SCRIPTS_DIR, "V-*.sh")) {
            for (Path entry : stream) {
                String name = entry.getFileName().toString();
                String code = name.replace(".sh", "");
                codes.add(code);
            }
        } catch (IOException e) {
            TrinetraCommon.logError("Failed to list V-codes: " + e.getMessage());
        }
        Collections.sort(codes);
        return codes;
    }

    public static boolean isKnownVCode(String vCode) {
        Path scriptPath = TrinetraCommon.HEX_SCRIPTS_DIR.resolve(vCode.toUpperCase() + ".sh");
        return Files.exists(scriptPath);
    }

    /** Dry-run: report what would happen without executing the script. */
    public static Map<String, Object> dryRun(String vCode, String sessionName, String target) {
        String sanitizedSession = TrinetraCommon.sanitizeName(sessionName);
        vCode = vCode.toUpperCase();
        Map<String, Object> result = TrinetraCommon.newMap();
        result.put("v_code", vCode);
        result.put("session", sanitizedSession);
        result.put("target", target);
        result.put("dry_run", true);

        // Check script exists
        Path scriptPath = TrinetraCommon.HEX_SCRIPTS_DIR.resolve(vCode + ".sh");
        result.put("script_exists", Files.exists(scriptPath));
        result.put("script_path", scriptPath.toString());

        // Check session exists
        Map<String, Object> session = TrinetraSession.loadSession(sanitizedSession);
        result.put("session_exists", session != null);

        // Check if already run
        Map<String, Object> brainState = TrinetraCommon.readJsonFile(
            TrinetraCommon.sessionBrainState(sanitizedSession));
        Object alreadyRun = brainState.get("already_run_v_codes");
        boolean alreadyRan = alreadyRun instanceof java.util.List && ((java.util.List<?>) alreadyRun).contains(vCode);
        result.put("already_run", alreadyRan);

        // Count existing findings
        List<Map<String, Object>> findings = TrinetraSession.getFindings(sanitizedSession);
        result.put("existing_findings_count", findings.size());

        // Script size estimate
        if (Files.exists(scriptPath)) {
            try {
                result.put("script_size_bytes", Files.size(scriptPath));
            } catch (IOException e) {
                result.put("script_size_bytes", -1);
            }
        }

        TrinetraCommon.logInfo("Dry-run " + vCode + ": script=" + Files.exists(scriptPath)
            + " session=" + (session != null) + " already_run=" + alreadyRan);
        return result;
    }

    private static String truncate(String s, int maxLen) {
        if (s == null) return "";
        return s.length() <= maxLen ? s : s.substring(0, maxLen - 3) + "...";
    }
}
