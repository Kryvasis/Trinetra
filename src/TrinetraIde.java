import java.io.*;
import java.nio.file.*;
import java.util.*;

/**
 * IDE and OpenCode-oriented helper layer.
 * Run/copy helpers, session-aware developer tooling, project convenience wrappers.
 */
public class TrinetraIde {

    public static String runScript(String scriptPath, String... args) {
        Path path = Path.of(scriptPath);
        if (!Files.exists(path)) {
            return "Script not found: " + scriptPath;
        }

        List<String> cmd = new ArrayList<>();
        cmd.add("bash");
        cmd.add(path.toString());
        for (String arg : args) cmd.add(arg);

        String[] result = TrinetraCommon.execCommand(60, cmd.toArray(new String[0]));
        return "Exit: " + result[2] + "\nStdout:\n" + result[0] + "\nStderr:\n" + result[1];
    }

    public static String copyToSession(String sourcePath, String sessionName) {
        String sanitized = TrinetraCommon.sanitizeName(sessionName);
        Path src = Path.of(sourcePath);
        if (!Files.exists(src)) {
            return "Source file not found: " + sourcePath;
        }

        Path destDir = TrinetraCommon.sessionArtifactsDir(sanitized);
        try {
            Files.createDirectories(destDir);
            Path dest = destDir.resolve(src.getFileName().toString());
            Files.copy(src, dest, StandardCopyOption.REPLACE_EXISTING);

            // Record in session JSON
            Map<String, Object> session = TrinetraSession.loadSession(sanitized);
            if (session != null) {
                session.put("updated_at", TrinetraCommon.nowIso());
                TrinetraCommon.writeJsonFile(TrinetraCommon.sessionJson(sanitized), session);
            }

            return "Copied to: " + dest;
        } catch (IOException e) {
            return "Copy failed: " + e.getMessage();
        }
    }

    public static String listSessionArtifacts(String sessionName) {
        String sanitized = TrinetraCommon.sanitizeName(sessionName);
        Path artDir = TrinetraCommon.sessionArtifactsDir(sanitized);
        if (!Files.exists(artDir)) {
            return "No artifacts directory for session: " + sanitized;
        }

        StringBuilder sb = new StringBuilder("Artifacts for session: " + sanitized + "\n\n");
        try {
            DirectoryStream<Path> stream = Files.newDirectoryStream(artDir);
            boolean found = false;
            for (Path entry : stream) {
                found = true;
                long size = Files.exists(entry) ? entry.toFile().length() : 0;
                sb.append("  ").append(entry.getFileName()).append(" (").append(size).append(" bytes)\n");
            }
            stream.close();
            if (!found) sb.append("  (empty)\n");
        } catch (IOException e) {
            sb.append("  Error listing: ").append(e.getMessage()).append("\n");
        }
        return sb.toString();
    }

    public static String getSessionSummary(String sessionName) {
        String sanitized = TrinetraCommon.sanitizeName(sessionName);
        Map<String, Object> session = TrinetraSession.loadSession(sanitized);
        if (session == null) return "Session not found: " + sanitized;

        StringBuilder sb = new StringBuilder();
        sb.append("Session: ").append(sanitized).append("\n");
        sb.append("Target: ").append(TrinetraCommon.getString(session, "target", "n/a")).append("\n");
        sb.append("Created: ").append(TrinetraCommon.getString(session, "created_at", "n/a")).append("\n");
        sb.append("Status: ").append(TrinetraCommon.getString(session, "status", "n/a")).append("\n");

        List<Map<String, Object>> findings = TrinetraSession.getFindings(sanitized);
        sb.append("Findings: ").append(findings.size()).append("\n");

        for (Map<String, Object> f : findings) {
            sb.append("  - ").append(TrinetraCommon.getString(f, "v_code", "???"))
              .append(" (").append(TrinetraCommon.getString(f, "status", "?")).append(")\n");
        }
        return sb.toString();
    }

    public static String listAllSessions() {
        StringBuilder sb = new StringBuilder("Trinetra Sessions:\n\n");
        try {
            DirectoryStream<Path> stream = Files.newDirectoryStream(TrinetraCommon.SESSIONS_DIR);
            boolean found = false;
            for (Path dir : stream) {
                if (Files.isDirectory(dir)) {
                    found = true;
                    String name = dir.getFileName().toString();
                    Path jsonPath = dir.resolve(name + ".json");
                    if (Files.exists(jsonPath)) {
                        Map<String, Object> session = TrinetraCommon.readJsonFile(jsonPath);
                        sb.append("  ").append(name)
                          .append(" [").append(TrinetraCommon.getString(session, "status", "?")).append("]")
                          .append(" target=").append(TrinetraCommon.getString(session, "target", "?"))
                          .append("\n");
                    } else {
                        sb.append("  ").append(name).append(" (no JSON)\n");
                    }
                }
            }
            stream.close();
            if (!found) sb.append("  (no sessions found)\n");
        } catch (IOException e) {
            sb.append("  Error: ").append(e.getMessage()).append("\n");
        }
        return sb.toString();
    }

    // ── OpenCode Prompt Strategy ──

    /** Build a structured prompt for code security analysis. */
    public static String buildSecurityAnalysisPrompt(String code, String context) {
        StringBuilder sb = new StringBuilder();
        sb.append("You are a security auditor analyzing code for vulnerabilities.\n\n");
        sb.append("CONTEXT: ").append(context != null ? context : "General security review").append("\n\n");
        sb.append("CODE TO ANALYZE:\n```\n").append(code).append("\n```\n\n");
        sb.append("Respond with a JSON object containing:\n");
        sb.append("- vulnerabilities: list of {type, severity, line, description, recommendation}\n");
        sb.append("- risk_score: 0-100 integer\n");
        sb.append("- summary: one-line assessment\n");
        sb.append("Return ONLY valid JSON, no markdown fences.");
        return sb.toString();
    }

    /** Build a structured prompt for V-code script review. */
    public static String buildVCodeReviewPrompt(String scriptContent, String vCode) {
        StringBuilder sb = new StringBuilder();
        sb.append("You are reviewing a pentest V-code script for correctness and safety.\n\n");
        sb.append("V-CODE: ").append(vCode).append("\n\n");
        sb.append("SCRIPT CONTENT:\n```bash\n").append(scriptContent).append("\n```\n\n");
        sb.append("Analyze and respond with a JSON object containing:\n");
        sb.append("- is_valid: boolean (does script follow contract: accepts session+target args, calls /api/command)\n");
        sb.append("- issues: list of {type, description, severity}\n");
        sb.append("- suggestions: list of improvement suggestions\n");
        sb.append("Return ONLY valid JSON, no markdown fences.");
        return sb.toString();
    }

    /** Build a structured prompt for session audit summary. */
    public static String buildAuditSummaryPrompt(String sessionJson, String brainMd) {
        StringBuilder sb = new StringBuilder();
        sb.append("You are generating an executive audit summary from pentest session data.\n\n");
        sb.append("SESSION DATA:\n").append(sessionJson).append("\n\n");
        sb.append("AUDIT BRAIN:\n").append(brainMd).append("\n\n");
        sb.append("Respond with a JSON object containing:\n");
        sb.append("- executive_summary: 2-3 sentence overview\n");
        sb.append("- critical_findings: list of high-severity issues\n");
        sb.append("- recommendations: prioritized list of remediation steps\n");
        sb.append("- risk_rating: Critical/High/Medium/Low\n");
        sb.append("Return ONLY valid JSON, no markdown fences.");
        return sb.toString();
    }

    /** Build a structured prompt for next-step reasoning. */
    public static String buildNextStepPrompt(String sessionState, List<String> availableVCodes) {
        StringBuilder sb = new StringBuilder();
        sb.append("You are recommending the next pentest step based on current session state.\n\n");
        sb.append("CURRENT STATE:\n").append(sessionState).append("\n\n");
        sb.append("AVAILABLE V-CODES: ").append(String.join(", ", availableVCodes)).append("\n\n");
        sb.append("Respond with a JSON object containing:\n");
        sb.append("- next_v_code: recommended V-code from the available list\n");
        sb.append("- reason: why this is the best next step\n");
        sb.append("- confidence: high/medium/low\n");
        sb.append("- requires_revalidation: boolean\n");
        sb.append("- based_on: what previous findings inform this recommendation\n");
        sb.append("Return ONLY valid JSON, no markdown fences.");
        return sb.toString();
    }

    /** Parse an AI JSON response, handling markdown fences and extracting JSON. */
    public static String extractJsonFromResponse(String response) {
        if (response == null) return null;
        String cleaned = response.strip();
        // Strip markdown code fences
        if (cleaned.startsWith("```")) {
            int firstNewline = cleaned.indexOf('\n');
            if (firstNewline > 0) cleaned = cleaned.substring(firstNewline + 1);
            if (cleaned.endsWith("```")) cleaned = cleaned.substring(0, cleaned.length() - 3);
        }
        // Find first { or [ to start of JSON
        int jsonStart = -1;
        for (int i = 0; i < cleaned.length(); i++) {
            char c = cleaned.charAt(i);
            if (c == '{' || c == '[') { jsonStart = i; break; }
        }
        if (jsonStart < 0) return cleaned.strip();
        return cleaned.substring(jsonStart).strip();
    }
}
