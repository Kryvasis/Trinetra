import java.nio.file.*;
import java.sql.*;
import java.util.*;
import java.util.concurrent.*;

/**
 * Tests for Prompt 12: test-selection (--tests/--test-file/--workers),
 * --list-tests catalog, parallel execution safety.
 *
 * Uses a hermetic synthetic environment inside the temp trinetra.root:
 * a minimal 2_static_map.json defining T-001..T-004 plus matching trivial
 * stat_scripts, so real 124-test bulk runs are never triggered here.
 *
 * Covers:
 *  (a) --tests subset: ONLY selected ids execute; unselected/unknown ids
 *      leave no trace in brain state or audit_log,
 *  (b) no selection: legacy run-everything behavior preserved (all codes,
 *      sorted, sequential),
 *  (c) parallel selected run + concurrent appends do not corrupt the
 *      brain-state hash chain (Prompt 10 pattern),
 *  (d) --list-tests emits valid parseable JSON with id/description/
 *      category/engine fields.
 */
public class TrinetraTestSelectionTest {

    private static int failures = 0;

    private static void expect(boolean cond, String what) {
        if (cond) {
            System.out.println("  [ok] " + what);
        } else {
            System.err.println("  [FAIL] " + what);
            failures++;
        }
    }

    private static final List<String> CODES =
        List.of("T-001", "T-002", "T-003", "T-004");

    public static void main(String[] args) throws Exception {
        Path root = Path.of(System.getProperty("trinetra.root"));
        System.out.println("=== TrinetraTestSelectionTest ===");
        System.out.println("root: " + root + "\n");

        setupSyntheticEnv(root);

        // ── (a) subset selection skips everything else ──────────
        System.out.println("(a) --tests T-001,T-003 (+unknown T-999) runs only selected");
        TrinetraAudit.beginNewRun();
        String uuidA = TrinetraAudit.currentRunUuid();
        TrinetraSession.createSession("tsel_a", "10.1.0.1");
        Set<String> selA = new LinkedHashSet<>(List.of("T-001", "t-003", "T-999"));
        List<Map<String, Object>> resA =
            TrinetraStat.statRunAll("tsel_a", "10.1.0.1", selA, 2, "alice");
        expect(resA.size() == 2, "only 2 tests executed (got " + resA.size() + ")");
        expect(ids(resA).equals(List.of("T-001", "T-003")),
            "executed ids exactly [T-001, T-003] -> " + ids(resA));

        List<String> ranA = ranCodes("tsel_a");
        expect(ranA.equals(List.of("T-001", "T-003")),
            "already_run_v_codes contains exactly the selected -> " + ranA);
        List<String> findingsA = findingCodes("tsel_a");
        expect(findingsA.equals(List.of("T-001", "T-003")),
            "findings contain exactly the selected");
        expect(!ranA.contains("T-002") && !ranA.contains("T-004")
               && !findingsA.contains("T-002") && !findingsA.contains("T-004"),
            "unselected tests fully absent from brain state");

        int auditedA = TrinetraAudit.countRows(uuidA);
        expect(auditedA == 2,
            "exactly 2 audit rows for the run (got " + auditedA + ")");
        expect(!auditMentions(uuidA, "T-002") && !auditMentions(uuidA, "T-004")
               && !auditMentions(uuidA, "T-999"),
            "skipped/unselected ids absent from audit_log");

        // ── (b) no selection preserves run-everything ───────────
        System.out.println("\n(b) omitting --tests preserves legacy full run");
        TrinetraAudit.beginNewRun();
        TrinetraSession.createSession("tsel_b", "10.1.0.2");
        // null selection = legacy run-everything; userId present exactly as
        // the CLI passes it, so per-test audit rows are emitted.
        List<Map<String, Object>> resB =
            TrinetraStat.statRunAll("tsel_b", "10.1.0.2", null, 1, "alice");
        expect(ids(resB).equals(CODES),
            "legacy path executed every definition in sorted order -> " + ids(resB));
        expect(ranCodes("tsel_b").equals(CODES),
            "brain contains all four codes");
        expect(TrinetraAudit.countRows(TrinetraAudit.currentRunUuid()) == 4,
            "per-test audit rows emitted for full run too (4)");

        // ── (c) parallel selected run keeps the chain intact ────
        System.out.println("\n(c) parallel execution does not corrupt hash chains");
        TrinetraAudit.beginNewRun();
        TrinetraSession.createSession("tsel_c", "10.1.0.3");
        Map<String, Object> seed = new LinkedHashMap<>();
        seed.put("device_id", "dev-x"); seed.put("vendor", "");
        seed.put("test_id", "V-000");   seed.put("raw_output", "");
        seed.put("normalized_result", "pass");
        seed.put("timestamp", "2026-08-22T00:00:00Z");

        ExecutorService pool = Executors.newFixedThreadPool(5);
        Future<?> runner = pool.submit(() ->
            TrinetraStat.statRunAll("tsel_c", "10.1.0.3",
                new LinkedHashSet<>(CODES), 4, "bob"));
        List<Future<Integer>> appenders = new ArrayList<>();
        for (int t = 0; t < 3; t++) {
            final int tid = t;
            appenders.add(pool.submit(() -> {
                int ok = 0;
                for (int i = 0; i < 3; i++) {
                    Map<String, Object> e = new LinkedHashMap<>(seed);
                    e.put("device_id", "dev-t" + tid + "-" + i);
                    if (TrinetraSession.appendNormalizedResult("tsel_c", e)) ok++;
                }
                return ok;
            }));
        }
        runner.get();
        int appended = 0;
        for (Future<Integer> f : appenders) appended += f.get();
        pool.shutdown();
        expect(pool.awaitTermination(120, TimeUnit.SECONDS), "pool drained");

        expect(appended == 9, "no concurrent appends lost (" + appended + "/9)");
        // 9 from appender threads + 4 from statRun (one per test executed)
        expect(TrinetraSession.getNormalizedResults("tsel_c").size() == 13,
            "normalized_results count intact (9 thread appends + 4 from statRun)");
        expect(ranCodes("tsel_c").equals(CODES),
            "all four selected tests ran under parallelism");
        TrinetraSession.ChainVerifyResult v = TrinetraSession.verifyChain("tsel_c");
        expect(v.intact && v.brokenAtIndex == -1,
            "verifyChain intact after parallel run -> " + v);
        TrinetraSession.ChainVerifyResult g = TrinetraSession.verifyGlobalChain();
        expect(g.intact, "verifyGlobalChain intact -> " + g);

        // ── (d) --list-tests structured JSON ────────────────────
        System.out.println("\n(d) --list-tests JSON catalog");
        String json = TrinetraStat.listTestsJson();
        Object parsed = TrinetraJson.parse(json);
        expect(parsed instanceof List, "catalog parses as a JSON array");
        boolean t001ok = false, shapeOk = true;
        Set<String> engines = new HashSet<>();
        if (parsed instanceof List) {
            for (Object o : (List<?>) parsed) {
                if (!(o instanceof Map)) { shapeOk = false; break; }
                Map<?, ?> m = (Map<?, ?>) o;
                if (!m.containsKey("id") || !m.containsKey("description")
                    || !m.containsKey("category") || !m.containsKey("engine")) {
                    shapeOk = false; break;
                }
                engines.add(String.valueOf(m.get("engine")));
                if ("T-001".equals(m.get("id"))
                    && !"Sensitive data via OSINT".equals(m.get("description"))) {
                    // description comes from our synthetic map below
                }
                if ("T-001".equals(m.get("id"))) t001ok = true;
            }
        }
        expect(shapeOk, "every entry has id/description/category/engine");
        expect(t001ok, "synthetic definition T-001 listed");
        expect(engines.contains("stat"), "engine field present (stat)");

        System.out.println();
        if (failures == 0) {
            System.out.println("[+] TrinetraTestSelectionTest: all tests passed");
            return;
        }
        System.err.println("[-] TrinetraTestSelectionTest: " + failures + " failure(s)");
        System.exit(1);
    }

    // ── helpers ──

    private static List<String> ids(List<Map<String, Object>> results) {
        List<String> out = new ArrayList<>();
        for (Map<String, Object> r : results)
            out.add(TrinetraCommon.getString(r, "v_code",
                TrinetraCommon.getString(r, "test_code", "?")));
        return out;
    }

    private static List<String> ranCodes(String session) {
        Map<String, Object> st = TrinetraCommon.readJsonFile(
            TrinetraCommon.sessionBrainState(session));
        List<String> codes = TrinetraCommon.getStringList(st, "already_run_v_codes");
        Collections.sort(codes);
        return codes;
    }

    private static List<String> findingCodes(String session) {
        List<String> out = new ArrayList<>();
        for (Map<String, Object> f : TrinetraSession.getFindings(session))
            out.add(TrinetraCommon.getString(f, "v_code",
                TrinetraCommon.getString(f, "test_code", "?")));
        Collections.sort(out);
        return out;
    }

    private static boolean auditMentions(String uuid, String needle) throws Exception {
        Class.forName("org.sqlite.JDBC");
        try (Connection c = DriverManager.getConnection(
                "jdbc:sqlite:" + TrinetraAudit.DB_PATH.toAbsolutePath());
             PreparedStatement ps = c.prepareStatement(
                 "SELECT count(*) FROM audit_log WHERE audit_uuid = ? "
                 + "AND (details LIKE ? OR session_name LIKE ?)")) {
            ps.setString(1, uuid);
            ps.setString(2, "%" + needle + "%");
            ps.setString(3, "%" + needle + "%");
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() && rs.getInt(1) > 0;
            }
        }
    }

    /** Minimal static map + scripts so the runner has something to run. */
    private static void setupSyntheticEnv(Path root) throws Exception {
        StringBuilder map = new StringBuilder("{\n");
        for (int i = 0; i < CODES.size(); i++) {
            String c = CODES.get(i);
            map.append("  \"").append(c).append("\": {\n")
               .append("    \"name\": \"Synthetic check ").append(c).append("\",\n")
               .append("    \"category\": \"synthetic\",\n")
               .append("    \"tool\": \"builtin\",\n")
               .append("    \"script\": \"").append(c).append(".sh\",\n")
               .append("    \"decision_rule\": {\n")
               .append("      \"method\": \"manual_review_required\",\n")
               .append("      \"pass_criteria\": \"\",\n")
               .append("      \"fail_criteria\": \"\"\n")
               .append("    },\n")
               .append("    \"default_severity\": \"Low\"\n")
               .append("  }").append(i + 1 < CODES.size() ? "," : "").append("\n");
        }
        map.append("}\n");
        Files.writeString(root.resolve("2_static_map.json"), map.toString());
        Files.writeString(root.resolve("3_decision_engine.csv"),
            "code,test_name,category,tool,script,eval_method,pass_criteria,"
            + "fail_criteria,default_severity,fallback_method,requires_external_tool\n");

        Path scripts = root.resolve("stat_scripts");
        Files.createDirectories(scripts);
        for (String c : CODES) {
            Files.writeString(scripts.resolve(c + ".sh"),
                "#!/bin/bash\n"
                + "echo \"output of " + c + "\"\n"
                + "[ -f \"$2/.block_" + c + "\" ] && exit 1\n"
                + "exit 0\n");
        }
    }
}
