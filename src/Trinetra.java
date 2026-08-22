import java.io.*;
import java.nio.file.*;
import java.util.*;

/**
 * Trinetra Beta — Primary orchestrator.
 * CLI entry point, state machine, session lifecycle, brain updates, -mind dispatcher,
 * and stat engine dispatch.
 *
 * Usage:
 *   trinetra -run                          Start HexStrike (make run)
 *   trinetra -stop                         Stop HexStrike (make stop)
 *   trinetra -status                       Check HexStrike status (make status)
 *   trinetra -pen -hex run <V-XXX> <session> <target>
 *   trinetra -stat run <V-XXX> <session> <target>
 *   trinetra -stat run-all <session> <target>
 *   trinetra -stat status <session>
 *   trinetra -mind -read <session> "query"
 *   trinetra -mind -update <session>
 *   trinetra -mind -suggest <session> "query"
 *   trinetra -mind -overall "query"
 *   trinetra -agr [cert] [session]
 *   trinetra -ide -r <script> [args...]
 *   trinetra -ide -cp <source> <session>
 *   trinetra -sessions
 *   trinetra -new <session> <target>
 *   trinetra -help
 */
public class Trinetra {

    public static void main(String[] args) {
        if (args.length == 0) {
            printUsage();
            return;
        }

        List<String> argList = new ArrayList<>(Arrays.asList(args));

        // -help
        if (argList.contains("-help") || argList.contains("--help")) {
            printUsage();
            return;
        }

        // -run → make run
        if (argList.contains("-run")) {
            runMake("run");
            return;
        }

        // -stop → make stop
        if (argList.contains("-stop")) {
            runMake("stop");
            return;
        }

        // -status → make status
        if (argList.contains("-status")) {
            runMake("status");
            return;
        }

        // -sessions
        if (argList.contains("-sessions")) {
            System.out.println(TrinetraIde.listAllSessions());
            return;
        }

        // -new <session> <target>
        int newIdx = argList.indexOf("-new");
        if (newIdx >= 0) {
            if (newIdx + 2 < argList.size()) {
                String session = argList.get(newIdx + 1);
                String target = argList.get(newIdx + 2);
                Map<String, Object> result = TrinetraSession.createSession(session, target);
                if (result != null) {
                    System.out.println("Session created: " + session + " (target: " + target + ")");
                } else {
                    System.err.println("Failed to create session: " + session);
                    System.exit(1);
                }
            } else {
                System.err.println("Usage: trinetra -new <session> <target>");
                System.exit(1);
            }
            return;
        }

        // -pen -hex run <V-XXX> <session> <target>
        if (argList.contains("-pen")) {
            handlePen(argList);
            return;
        }

        // -stat run <V-XXX> <session> <target> | run-all <session> <target> | status <session>
        if (argList.contains("-stat")) {
            handleStat(argList);
            return;
        }

        // -mind ...
        if (argList.contains("-mind")) {
            handleMind(argList);
            return;
        }

        // -agr [cert] [session]
        if (argList.contains("-agr")) {
            handleAgr(argList);
            return;
        }

        // -ide ...
        if (argList.contains("-ide")) {
            handleIde(argList);
            return;
        }

        // -doctor
        if (argList.contains("-doctor")) {
            handleDoctor();
            return;
        }

        System.err.println("Unknown command. Use 'trinetra -help' for usage.");
        System.exit(1);
    }

    private static void handlePen(List<String> args) {
        int runIdx = args.indexOf("run");
        if (runIdx < 0) {
            System.err.println("Usage: trinetra -pen -hex run <V-XXX> <session> <target> [--dry-run]");
            System.exit(1);
            return;
        }

        if (runIdx + 3 >= args.size()) {
            System.err.println("Usage: trinetra -pen -hex run <V-XXX> <session> <target> [--dry-run]");
            System.exit(1);
            return;
        }

        String vCode = args.get(runIdx + 1);
        String session = args.get(runIdx + 2);
        String target = args.get(runIdx + 3);
        boolean dryRun = args.contains("--dry-run");

        if (dryRun) {
            Map<String, Object> result = TrinetraPen.dryRun(vCode, session, target);
            System.out.println("=== Dry Run: " + vCode + " ===");
            System.out.println("Script exists: " + result.get("script_exists"));
            System.out.println("Script path: " + result.get("script_path"));
            System.out.println("Session exists: " + result.get("session_exists"));
            System.out.println("Already run: " + result.get("already_run"));
            System.out.println("Existing findings: " + result.get("existing_findings_count"));
            if ((Boolean) result.get("script_exists")) {
                System.out.println("Script size: " + result.get("script_size_bytes") + " bytes");
            }
            return;
        }

        Map<String, Object> finding = TrinetraPen.run(vCode, session, target);

        if (finding != null) {
            String status = TrinetraCommon.getString(finding, "status", "unknown");
            String summary = TrinetraCommon.getString(finding, "summary", null);

            System.out.println("=== " + vCode + " Result ===");
            System.out.println("Status: " + status);
            System.out.println("Summary status: " + TrinetraCommon.getString(finding, "summary_status", "?"));
            if (summary != null && !summary.isEmpty()) {
                System.out.println("Summary: " + summary);
            } else {
                System.out.println("Summary: (not available)");
            }

            // Auto-trigger brain update
            String sanitized = TrinetraCommon.sanitizeName(session);
            TrinetraBrain.updateBrain(sanitized);
            System.out.println("\nBrain updated.");
        } else {
            System.err.println("Run failed — no finding record produced.");
            System.exit(1);
        }
    }

    private static void handleStat(List<String> args) {
        if (args.contains("run")) {
            int runIdx = args.indexOf("run");
            if (runIdx + 3 >= args.size()) {
                System.err.println("Usage: trinetra -stat run <V-XXX> <session> <target>");
                System.exit(1);
                return;
            }
            String vCode = args.get(runIdx + 1);
            String session = args.get(runIdx + 2);
            String target = args.get(runIdx + 3);

            Map<String, Object> finding = TrinetraStat.statRun(vCode, session, target);
            if (finding != null) {
                String verdict = TrinetraCommon.getString(finding, "verdict", "unknown");
                String detail = TrinetraCommon.getString(finding, "verdict_detail", "");
                System.out.println("=== " + vCode + " Stat Result ===");
                System.out.println("Verdict: " + verdict.toUpperCase());
                if (!detail.isEmpty()) System.out.println("Detail: " + detail);
            } else {
                System.err.println("Stat run failed — no finding produced.");
                System.exit(1);
            }
            return;
        }

        if (args.contains("run-all")) {
            int idx = args.indexOf("run-all");
            if (idx + 2 >= args.size()) {
                System.err.println("Usage: trinetra -stat run-all <session> <target>");
                System.exit(1);
                return;
            }
            String session = args.get(idx + 1);
            String target = args.get(idx + 2);
            TrinetraStat.statRunAll(session, target);
            return;
        }

        if (args.contains("status")) {
            int idx = args.indexOf("status");
            if (idx + 1 >= args.size()) {
                System.err.println("Usage: trinetra -stat status <session>");
                System.exit(1);
                return;
            }
            String session = args.get(idx + 1);
            System.out.println(TrinetraStat.statStatus(session));
            return;
        }

        System.err.println("Usage: trinetra -stat <run|run-all|status> [args]");
        System.exit(1);
    }

    private static void handleMind(List<String> args) {
        if (args.contains("-read")) {
            int idx = args.indexOf("-read");
            if (idx + 2 >= args.size()) {
                System.err.println("Usage: trinetra -mind -read <session> \"query\"");
                System.exit(1);
                return;
            }
            String session = args.get(idx + 1);
            String query = args.get(idx + 2);
            System.out.println(TrinetraBrain.queryBrain(session, query));
            return;
        }

        if (args.contains("-update")) {
            int idx = args.indexOf("-update");
            if (idx + 1 >= args.size()) {
                System.err.println("Usage: trinetra -mind -update <session>");
                System.exit(1);
                return;
            }
            String session = args.get(idx + 1);
            boolean ok = TrinetraBrain.updateBrain(session);
            System.out.println(ok ? "Brain updated successfully." : "Brain update failed.");
            return;
        }

        if (args.contains("-suggest")) {
            int idx = args.indexOf("-suggest");
            if (idx + 1 >= args.size()) {
                System.err.println("Usage: trinetra -mind -suggest <session> [\"query\"]");
                System.exit(1);
                return;
            }
            String session = args.get(idx + 1);
            // Optional query arg after session name
            String query = null;
            if (idx + 2 < args.size()) {
                String next = args.get(idx + 2);
                if (!next.startsWith("-")) {
                    query = next;
                }
            }
            if (query != null) {
                // Build enriched suggestion with query context
                System.out.println(TrinetraBrain.suggestNext(session));
            } else {
                System.out.println(TrinetraBrain.suggestNext(session));
            }
            return;
        }

        if (args.contains("-overall")) {
            int idx = args.indexOf("-overall");
            if (idx + 1 >= args.size()) {
                System.err.println("Usage: trinetra -mind -overall \"query\"");
                System.exit(1);
                return;
            }
            String query = args.get(idx + 1);
            System.out.println(TrinetraBrain.queryOverall(query));
            return;
        }

        if (args.contains("-score")) {
            int idx = args.indexOf("-score");
            if (idx + 1 >= args.size()) {
                System.err.println("Usage: trinetra -mind -score <session>");
                System.exit(1);
                return;
            }
            String session = args.get(idx + 1);
            Map<String, Object> score = TrinetraBrain.brainScore(session);
            String scoreVal = TrinetraCommon.getString(score, "score", "?");
            System.out.println("=== Brain Score: " + session + " ===");
            System.out.println("Score: " + scoreVal + "/100");
            System.out.println("Total tests: " + TrinetraCommon.getString(score, "total_tests", "0"));
            System.out.println("Passed: " + TrinetraCommon.getString(score, "passed", "0"));
            System.out.println("Failed: " + TrinetraCommon.getString(score, "failed", "0"));
            System.out.println("Manual review: " + TrinetraCommon.getString(score, "manual_review", "0"));
            System.out.println("Critical: " + TrinetraCommon.getString(score, "critical_count", "0"));
            System.out.println("High: " + TrinetraCommon.getString(score, "high_count", "0"));
            @SuppressWarnings("unchecked")
            List<String> cves = (List<String>) score.get("cve_matches");
            if (cves != null && !cves.isEmpty()) {
                System.out.println("CVE matches: " + String.join(", ", cves));
            }
            @SuppressWarnings("unchecked")
            List<String> certIssues = (List<String>) score.get("cert_issues");
            if (certIssues != null && !certIssues.isEmpty()) {
                System.out.println("Cert issues: " + String.join(", ", certIssues));
            }
            return;
        }

        System.err.println("Usage: trinetra -mind <-read|-update|-suggest|-overall|-score> [args]");
        System.exit(1);
    }

    private static void handleAgr(List<String> args) {
        int agrIdx = args.indexOf("-agr");
        String certMode = "default";
        String session = null;

        for (int i = agrIdx + 1; i < args.size(); i++) {
            String a = args.get(i);
            if (a.startsWith("-")) continue;
            if (certMode.equals("default") && !a.contains("/")) {
                if (a.equalsIgnoreCase("stig") || a.equalsIgnoreCase("cis") || a.equalsIgnoreCase("default")) {
                    certMode = a;
                } else {
                    session = a;
                }
            } else if (session == null) {
                session = a;
            }
        }

        if (session == null) {
            System.err.println("Usage: trinetra -agr [cert] <session>");
            System.exit(1);
            return;
        }

        // Generate both scorecard and detailed report
        String report = TrinetraAgr.generateReport(session, certMode);
        System.out.println(report);

        // Show where files were saved
        String sanitized = TrinetraCommon.sanitizeName(session);
        Path artifactsDir = TrinetraCommon.sessionArtifactsDir(sanitized);
        System.out.println("\n--- Files saved ---");
        System.out.println("Report:      " + artifactsDir.resolve("pentest_report_" + sanitized + ".md"));
        System.out.println("JSON:        " + artifactsDir.resolve("report_" + sanitized + ".json"));
        System.out.println("Scorecard:   " + TrinetraCommon.sessionDir(sanitized).resolve("scorecard_" + sanitized + ".md"));
    }

    private static void handleIde(List<String> args) {
        int ideIdx = args.indexOf("-ide");

        if (args.contains("-r")) {
            int rIdx = args.indexOf("-r");
            if (rIdx + 1 >= args.size()) {
                System.err.println("Usage: trinetra -ide -r <script> [args...]");
                System.exit(1);
                return;
            }
            String script = args.get(rIdx + 1);
            List<String> scriptArgs = new ArrayList<>();
            for (int i = rIdx + 2; i < args.size(); i++) {
                if (args.get(i).startsWith("-")) break;
                scriptArgs.add(args.get(i));
            }
            System.out.println(TrinetraIde.runScript(script, scriptArgs.toArray(new String[0])));
            return;
        }

        if (args.contains("-cp")) {
            int cpIdx = args.indexOf("-cp");
            if (cpIdx + 2 >= args.size()) {
                System.err.println("Usage: trinetra -ide -cp <source> <session>");
                System.exit(1);
                return;
            }
            String source = args.get(cpIdx + 1);
            String session = args.get(cpIdx + 2);
            System.out.println(TrinetraIde.copyToSession(source, session));
            return;
        }

        if (args.contains("-sessions")) {
            System.out.println(TrinetraIde.listAllSessions());
            return;
        }

        System.err.println("Usage: trinetra -ide <-r|-cp|-sessions> [args]");
        System.exit(1);
    }

    private static void handleDoctor() {
        System.out.println("=== Trinetra Doctor Diagnostics ===\n");

        // 1. Check project structure
        System.out.println("[1] Project Structure");
        File root = new File(TrinetraCommon.PROJECT_ROOT);
        System.out.println("  Root: " + root.getAbsolutePath() + " — " + (root.exists() ? "OK" : "MISSING"));
        File srcDir = new File(root, "src");
        System.out.println("  src/: " + (srcDir.exists() ? "OK" : "MISSING"));
        File hexDir = new File(root, "hex_scripts");
        System.out.println("  hex_scripts/: " + (hexDir.exists() ? "OK" : "MISSING"));
        File statDir = new File(root, "stat_scripts");
        System.out.println("  stat_scripts/: " + (statDir.exists() ? "OK" : "MISSING"));
        File outDir = new File(root, "out");
        System.out.println("  out/: " + (outDir.exists() ? "OK" : "MISSING"));
        File sessionsDir = new File(root, "sessions");
        System.out.println("  sessions/: " + (sessionsDir.exists() ? "OK" : "MISSING"));

        // 2. Check Java compilation
        System.out.println("\n[2] Compilation");
        File trinetraClass = new File(outDir, "Trinetra.class");
        System.out.println("  Compiled classes: " + (trinetraClass.exists() ? "OK" : "MISSING (run 'make compile')"));

        // 3. Check HexStrike config
        System.out.println("\n[3] HexStrike Configuration");
        File hexStrikeDir = new File(System.getProperty("user.home"), ".hexsrtike");
        System.out.println("  Config dir: " + hexStrikeDir.getAbsolutePath() + " — " + (hexStrikeDir.exists() ? "OK" : "MISSING"));
        File apiKeyFile = new File(hexStrikeDir, "openrouter_api_key");
        if (apiKeyFile.exists()) {
            System.out.println("  API key: EXISTS (" + apiKeyFile.length() + " bytes)");
        } else {
            System.out.println("  API key: MISSING");
        }

        // 4. Check V-code scripts
        System.out.println("\n[4] V-Code Scripts");
        List<String> vCodes = TrinetraPen.listVCodes();
        System.out.println("  Hex scripts: " + vCodes.size() + " scripts");
        if (vCodes.isEmpty()) {
            System.out.println("  WARNING: No V-code scripts found in hex_scripts/");
        }
        TrinetraStat.loadDefinitions();
        List<String> statCodes = TrinetraStat.listStatCodes();
        System.out.println("  Stat scripts: " + statCodes.size() + " definitions");
        if (statCodes.isEmpty()) {
            System.out.println("  WARNING: No stat definitions loaded");
        }

        // 5. Validate sessions
        System.out.println("\n[5] Session Validation");
        Map<String, List<String>> validationErrors = TrinetraSession.validateAllSessions();
        if (validationErrors.isEmpty()) {
            System.out.println("  All sessions valid");
        } else {
            for (Map.Entry<String, List<String>> entry : validationErrors.entrySet()) {
                System.out.println("  " + entry.getKey() + ": " + entry.getValue().size() + " errors");
                for (String err : entry.getValue()) {
                    System.out.println("    - " + err);
                }
            }
        }

        // 6. Check Gemini CLI
        System.out.println("\n[6] AI Integration");
        String geminiPath = System.getProperty("user.home") + "/.npm-global/bin/gemini";
        File geminiCli = new File(geminiPath);
        System.out.println("  Gemini CLI: " + (geminiCli.exists() ? "INSTALLED" : "NOT FOUND (OpenRouter fallback available)"));
        String geminiKey = System.getenv("GEMINI_API_KEY");
        if (geminiKey == null) {
            // Check settings.json
            File settingsFile = new File(System.getProperty("user.home"), ".gemini/settings.json");
            if (settingsFile.exists()) {
                System.out.println("  GEMINI_API_KEY: SET (via ~/.gemini/settings.json)");
            } else {
                System.out.println("  GEMINI_API_KEY: NOT SET (OpenRouter fallback available)");
            }
        } else {
            System.out.println("  GEMINI_API_KEY: SET (via environment)");
        }

        // 7. Check HexStrike server
        System.out.println("\n[7] HexStrike Server");
        String[] statusResult = TrinetraCommon.execCommand(5, "pgrep", "-f", "hexstrike_server");
        boolean running = !statusResult[0].strip().isEmpty();
        System.out.println("  Server: " + (running ? "RUNNING (PID " + statusResult[0].strip() + ")" : "NOT RUNNING"));

        System.out.println("\n=== Doctor Complete ===");
    }

    private static void runMake(String target) {
        String projectRoot = TrinetraCommon.PROJECT_ROOT;
        String[] result = TrinetraCommon.execCommand(30, "make", "-C", projectRoot, target);
        if (!result[0].isEmpty()) System.out.print(result[0]);
        if (!result[1].isEmpty()) System.err.print(result[1]);
        int exitCode;
        try { exitCode = Integer.parseInt(result[2]); } catch (Exception e) { exitCode = -1; }
        System.exit(exitCode);
    }

    private static void printUsage() {
        System.out.println("Trinetra Beta — Modular Pentesting Framework\n");
        System.out.println("Usage:\n");
        System.out.println("  trinetra -run                           Start HexStrike server");
        System.out.println("  trinetra -stop                          Stop HexStrike server");
        System.out.println("  trinetra -status                        Check HexStrike status");
        System.out.println("  trinetra -new <session> <target>        Create a new session");
        System.out.println("  trinetra -sessions                      List all sessions");
        System.out.println("  trinetra -pen -hex run <V> <sess> <tgt> Run a pen V-code against target");
        System.out.println("  trinetra -stat run <V> <sess> <tgt>     Run a stat V-code against target");
        System.out.println("  trinetra -stat run-all <sess> <tgt>     Run all stat tests sequentially");
        System.out.println("  trinetra -stat status <sess>            Print stat pass/fail tally");
        System.out.println("  trinetra -mind -read <sess> \"query\"      Query session audit brain");
        System.out.println("  trinetra -mind -update <sess>           Force brain refresh");
        System.out.println("  trinetra -mind -suggest <sess>          Get next V-code suggestion");
        System.out.println("  trinetra -mind -overall \"query\"         Query global activity");
        System.out.println("  trinetra -mind -score <sess>            CVE/certificate scoring");
        System.out.println("  trinetra -agr [cert] <sess>             Generate scorecard");
        System.out.println("  trinetra -ide -r <script> [args...]     Run a script");
        System.out.println("  trinetra -ide -cp <src> <sess>          Copy file to session artifacts");
        System.out.println("  trinetra -doctor                        Run diagnostics");
        System.out.println("  trinetra -help                          Show this help\n");
        System.out.println("Options:");
        System.out.println("  --dry-run                            Preview V-code execution without running\n");
        System.out.println("V-codes: V-001 through V-158 (see hex_scripts/ and stat_scripts/)");
        System.out.println("Cert modes: default, stig (beta)");
    }
}
