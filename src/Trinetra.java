import java.io.*;
import java.nio.file.*;
import java.util.*;

/**
 * Trinetra Beta — Primary orchestrator.
 * CLI entry point, state machine, session lifecycle, brain updates, -mind dispatcher,
 * and stat engine dispatch.
 *
 * Usage:
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

        // -sessions
        if (argList.contains("-sessions")) {
            System.out.println(TrinetraIde.listAllSessions());
            return;
        }

        // --list-tests: structured JSON catalog of runnable test ids
        // (consumed by the future React UI via the Flask bridge).
        if (argList.contains("--list-tests")) {
            System.out.println(TrinetraStat.listTestsJson());
            return;
        }

        // --tests <a,b,c> / --test-file <path> / --workers <N>
        Set<String> testSelection = extractTestSelection(argList);
        int workers = extractWorkers(argList);

        // --user / -u <name>  (audit identity for this invocation)
        // Falls back to the OS username rather than blocking execution;
        // the chosen identity source is always logged.
        String userId = extractUserId(argList);

        // -new <session> <target>
        int newIdx = argList.indexOf("-new");
        if (newIdx >= 0) {
            if (newIdx + 2 < argList.size()) {
                String session = argList.get(newIdx + 1);
                String target = argList.get(newIdx + 2);
                Map<String, Object> result = TrinetraSession.createSession(session, target);
                if (result != null) {
                    System.out.println("Session created: " + session + " (target: " + target + ")");
                    TrinetraAudit.sessionStart(userId,
                        TrinetraCommon.sanitizeName(session), target);
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

        // -stat run <V-XXX> <session> <target> | run-all <session> <target> | status <session>
        if (argList.contains("-stat")) {
            handleStat(argList, userId, testSelection, workers);
            return;
        }

        // -mind ...
        if (argList.contains("-mind")) {
            handleMind(argList);
            return;
        }

        // -agr [cert] [session]
        if (argList.contains("-agr")) {
            handleAgr(argList, userId);
            return;
        }

        // -ide ...
        if (argList.contains("-ide")) {
            handleIde(argList);
            return;
        }

        // -compliance-score <session>
        if (argList.contains("-compliance-score")) {
            handleComplianceScore(argList);
            return;
        }

        // -compliance-report <session>  (scorer + validated LLM narrative)
        if (argList.contains("-compliance-report")) {
            handleComplianceReport(argList);
            return;
        }

        // -audit-report <session>  (final deliverable: per-framework reports
        // + combined appended audit report; runs scorer -> narrative -> build)
        if (argList.contains("-audit-report")) {
            handleAuditReport(argList, userId);
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

    /**
     * Extract (and remove) --tests <id,id,...> from the argument list.
     * Empty/absent -> null, meaning "no selection" (legacy run-everything).
     */
    static Set<String> extractTestSelection(List<String> args) {
        return extractListArg(args, "--tests");
    }

    /**
     * Extract (and remove) --test-file <path>; the file may hold one id
     * per line or a comma-separated list; blank lines and #-comments are
     * ignored.  Combined with any --tests ids into one ordered set.
     */
    static Set<String> extractTestSelectionWithFile(List<String> args) {
        Set<String> out = new LinkedHashSet<>();
        Set<String> inline = extractTestSelection(args);
        if (inline != null) out.addAll(inline);

        for (int i = 0; i < args.size(); i++) {
            if (args.get(i).equals("--test-file") && i + 1 < args.size()) {
                Path file = Path.of(args.get(i + 1));
                args.remove(i);
                args.remove(i);
                try {
                    for (String line : Files.readAllLines(file)) {
                        String t = line.trim();
                        if (t.isEmpty() || t.startsWith("#")) continue;
                        for (String id : t.split(",")) {
                            String idT = id.trim();
                            if (!idT.isEmpty()) out.add(idT.toUpperCase());
                        }
                    }
                } catch (IOException e) {
                    System.err.println("Cannot read test file " + file + ": " + e.getMessage());
                    System.exit(1);
                }
                break;
            }
        }
        return out.isEmpty() ? null : out;
    }

    /** Extract (and remove) --workers <N>; default 4. */
    static int extractWorkers(List<String> args) {
        for (int i = 0; i < args.size(); i++) {
            if (args.get(i).equals("--workers") && i + 1 < args.size()) {
                int n;
                try { n = Integer.parseInt(args.get(i + 1)); }
                catch (NumberFormatException e) { n = 4; }
                args.remove(i);
                args.remove(i);
                return Math.max(1, n);
            }
        }
        return 4;
    }

    private static Set<String> extractListArg(List<String> args, String flag) {
        for (int i = 0; i < args.size(); i++) {
            if (args.get(i).equals(flag) && i + 1 < args.size()) {
                Set<String> out = new LinkedHashSet<>();
                for (String id : args.get(i + 1).split(",")) {
                    String t = id.trim();
                    if (!t.isEmpty()) out.add(t.toUpperCase());
                }
                args.remove(i);
                args.remove(i);
                return out;
            }
        }
        return null;
    }

    /**
     * Extract (and remove) the --user/-u <name> pair from the argument
     * list.  Falls back to the OS username when absent; the identity
     * source actually used is logged either way.
     */
    static String extractUserId(List<String> args) {
        String explicit = null;
        for (int i = 0; i < args.size(); i++) {
            String a = args.get(i);
            if ((a.equals("--user") || a.equals("-u")) && i + 1 < args.size()) {
                explicit = args.get(i + 1);
                args.remove(i);      // flag
                args.remove(i);      // value
                break;
            }
        }
        if (explicit != null && !explicit.isBlank()) {
            System.out.println("[audit] user: " + explicit + " (--user flag)");
            return explicit;
        }
        String osUser = System.getProperty("user.name", "unknown");
        System.out.println("[audit] user: " + osUser + " (OS username fallback)");
        return osUser;
    }

    private static void handleStat(List<String> args, String userId,
                                   Set<String> testSelection, int workers) {
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
                TrinetraAudit.testExecuted(userId, session, vCode, verdict);
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
                System.err.println("Usage: trinetra -stat run-all <session> <target> [--tests <ids>] [--test-file <path>] [--workers <N>]");
                System.exit(1);
                return;
            }
            String session = args.get(idx + 1);
            String target = args.get(idx + 2);

            // Per-test audit rows are written inside the runner (Prompt 11
            // path); selection comes from --tests/--test-file, parallelism
            // from --workers (default 4).
            TrinetraStat.statRunAll(session, target, testSelection, workers, userId);
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

    private static void handleAgr(List<String> args, String userId) {
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

        // Session completion: final audit row linking to the brain-state chain
        TrinetraAudit.sessionEnd(userId, session,
            "report generated, cert=" + certMode);

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

        // 3. Check test definitions
        System.out.println("\n[3] Test Definitions");
        TrinetraStat.loadDefinitions();
        List<String> statCodes = TrinetraStat.listStatCodes();
        System.out.println("  Stat scripts: " + statCodes.size() + " definitions");
        if (statCodes.isEmpty()) {
            System.out.println("  WARNING: No stat definitions loaded");
        }

        // 4. Validate sessions
        System.out.println("\n[4] Session Validation");
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

        // 5. Check AI integration
        System.out.println("\n[5] AI Integration");
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
        Path orKey = TrinetraCommon.TRI_CONFIG_DIR.resolve("openrouter_api_key");
        if (Files.exists(orKey)) {
            System.out.println("  OpenRouter key: SET (via ~/.trinetra/openrouter_api_key)");
        } else {
            System.out.println("  OpenRouter key: NOT SET (Gemini-only mode)");
        }

        System.out.println("\n=== Doctor Complete ===");
    }

    private static void handleComplianceScore(List<String> args) {
        int idx = args.indexOf("-compliance-score");
        if (idx < 0 || idx + 1 >= args.size()) {
            System.err.println("Usage: trinetra -compliance-score <session>");
            System.exit(1);
        }
        String session = args.get(idx + 1);
        Map<String, Object> result = TrinetraComplianceScorer.score(session);
        Path outPath = TrinetraComplianceScorer.scoreAndWrite(session);
        System.out.println(TrinetraJson.prettyJson(result));
        System.out.println("\nCompliance score written to: " + outPath);
    }

    /**
     * -compliance-report <session>
     * Runs the deterministic compliance scorer (Prompt 15) and then the
     * validated LLM narrative layer (Prompt 16). The narrative never alters
     * scorer numbers; on LLM rejection/unavailability a template fallback
     * built from the same data is used and clearly labeled.
     */
    private static void handleComplianceReport(List<String> args) {
        int idx = args.indexOf("-compliance-report");
        if (idx < 0 || idx + 1 >= args.size()) {
            System.err.println("Usage: trinetra -compliance-report <session>");
            System.exit(1);
        }
        String session = args.get(idx + 1);

        System.out.println("[1/2] Running deterministic compliance scorer...");
        Path scorePath = TrinetraComplianceScorer.scoreAndWrite(session);
        Map<String, Object> score = TrinetraComplianceScorer.score(session);

        System.out.println("[2/2] Generating narrative layer (LLM with strict number validation)...");
        Map<String, Object> meta =
            TrinetraNarrativeGenerator.generateReport(session, score);

        String source = TrinetraCommon.getString(meta, "source", "?");
        String fallbackReason = TrinetraCommon.getString(meta, "fallback_reason", "");
        List<String> rejected = TrinetraCommon.getStringList(meta, "rejected_numbers_first_attempt");

        System.out.println("\n=== Compliance Narrative Report ===");
        System.out.println("Session: " + session);
        System.out.println("Narrative source: "
            + (TrinetraNarrativeGenerator.SOURCE_LLM.equals(source)
                ? "Gemini LLM (number-validated)"
                : fallbackReason));
        if (TrinetraNarrativeGenerator.SOURCE_LLM.equals(source)) {
            System.out.println("Validation: PASS (attempts: "
                + TrinetraCommon.getInt(meta, "attempts", 0) + ")");
        }
        if (!rejected.isEmpty()) {
            System.out.println("Rejected numbers (first attempt): " + rejected);
        }

        Path reportPath = Path.of(TrinetraCommon.getString(meta, "path", ""));
        String content = TrinetraCommon.readFileIfExists(reportPath);
        if (content != null) {
            System.out.println();
            System.out.println(content);
        }

        System.out.println("--- Files saved ---");
        System.out.println("Score JSON: " + scorePath);
        System.out.println("Narrative:  " + reportPath);
    }

    /**
     * -audit-report <session>
     * Assembles the final deliverable audit report set (Prompt 17):
     * ensures scorer + narrative artifacts exist for the session, then
     * writes one per-framework report plus the combined appended audit
     * report with executive summary, unmapped-tests section, and a
     * tamper-evidence appendix. Derived artifacts only — never touches
     * brain state or the hash chain.
     */
    private static void handleAuditReport(List<String> args, String userId) {
        int idx = args.indexOf("-audit-report");
        if (idx < 0 || idx + 1 >= args.size()) {
            System.err.println("Usage: trinetra -audit-report <session>");
            System.exit(1);
            return;
        }
        String session = args.get(idx + 1);

        System.out.println("[1/3] Ensuring deterministic compliance score exists...");
        Map<String, Object> result = TrinetraAuditReportBuilder.buildAuditReport(session);
        if (result == null) {
            System.err.println("Failed: no readable brain-state record for session '"
                + session + "'. Run tests first (trinetra -stat ...).");
            System.exit(1);
            return;
        }

        // Session completion row links this generation run into audit_log.
        TrinetraAudit.sessionEnd(userId, session,
            "audit_report generated, frameworks="
                + TrinetraCommon.getInt(result, "frameworks", 0));

        System.out.println("\n=== Audit Report Generated ===");
        System.out.println("Session:           " + TrinetraCommon.getString(result, "session_name", session));
        System.out.println("Combined report:   " + TrinetraCommon.getString(result, "combined_path", "?"));
        System.out.println("Derived aggregate: "
            + TrinetraCommon.getString(result, "derived_aggregate_pct", "?") + "% (report-builder computed)");
        System.out.println("Narrative source:  " + TrinetraCommon.getString(result, "narrative_source", "?"));
        System.out.println("Chain status:      " + TrinetraCommon.getString(result, "chain_status", "?"));
        System.out.println("\nPer-framework reports:");
        for (String p : TrinetraCommon.getStringList(result, "framework_paths")) {
            System.out.println("  - " + p);
        }
        List<String> skipped = TrinetraCommon.getStringList(result, "skipped_frameworks");
        if (!skipped.isEmpty()) {
            System.out.println("Skipped (no mapped tests): " + String.join(", ", skipped));
        }
    }

    private static void printUsage() {
        System.out.println("Trinetra Beta — AI-Driven Multi-Vendor Network Security Compliance Auditor\n");
        System.out.println("Usage:\n");
        System.out.println("  trinetra -new <session> <target>        Create a new session");
        System.out.println("  trinetra -sessions                      List all sessions");
        System.out.println("  trinetra -stat run <V> <sess> <tgt>     Run a stat V-code against target");
        System.out.println("  trinetra -stat run-all <sess> <tgt>     Run all stat tests sequentially");
        System.out.println("  trinetra -stat status <sess>            Print stat pass/fail tally");
        System.out.println("  trinetra -mind -read <sess> \"query\"      Query session audit brain");
        System.out.println("  trinetra -mind -update <sess>           Force brain refresh");
        System.out.println("  trinetra -mind -suggest <sess>          Get next V-code suggestion");
        System.out.println("  trinetra -mind -overall \"query\"         Query global activity");
        System.out.println("  trinetra -mind -score <sess>            CVE/certificate scoring");
        System.out.println("  trinetra -agr [cert] <sess>             Generate scorecard");
        System.out.println("  trinetra -compliance-score <sess>       Score session compliance (deterministic)");
        System.out.println("  trinetra -compliance-report <sess>      Scorer + AI narrative report (validated)");
        System.out.println("  trinetra -audit-report <sess>           Final deliverable: per-framework + combined audit report");
        System.out.println("  trinetra -ide -r <script> [args...]     Run a script");
        System.out.println("  trinetra -ide -cp <src> <sess>          Copy file to session artifacts");
        System.out.println("  trinetra -doctor                        Run diagnostics");
        System.out.println("  trinetra -help                          Show this help\n");
        System.out.println("Options:");
        System.out.println("  --dry-run                            Preview V-code execution without running\n");
        System.out.println("V-codes: compliance-relevant set defined in 2_static_map.json / 3_decision_engine.csv (stat_scripts/)");
        System.out.println("Cert modes: default, stig (beta)");
    }
}
