import java.nio.file.*;
import java.util.*;

/**
 * Tests for the optional brain-state `normalized_results` field.
 *
 * Run with:
 *   javac -cp out -d out tests/TrinetraNormalizedResultsTest.java
 *   java -Dtrinetra.root=<temp-root> -cp out TrinetraNormalizedResultsTest
 *
 * Covers:
 *  (a) appending an entry persists it to brain_state_<name>.json,
 *  (b) all 14 required brain-state fields remain intact/valid after append,
 *  (c) an old brain-state file without normalized_results loads and
 *      validates cleanly (treated as empty array).
 */
public class TrinetraNormalizedResultsTest {

    private static final List<String> REQUIRED_14 = List.of(
        "session_name", "target", "state", "last_updated",
        "byte_size", "estimated_tokens", "compression_count",
        "already_run_v_codes", "confirmed_findings", "suspected_findings",
        "counts", "latest_suggestion", "suggestion_history", "latest_score");

    private static int failures = 0;

    private static void expect(boolean cond, String what) {
        if (cond) {
            System.out.println("  [ok] " + what);
        } else {
            System.err.println("  [FAIL] " + what);
            failures++;
        }
    }

    private static Map<String, Object> sampleEntry(String deviceId) {
        Map<String, Object> e = new LinkedHashMap<>();
        e.put("device_id", deviceId);
        e.put("vendor", "Cisco");
        e.put("test_id", "V-003");
        e.put("raw_output", "raw banner bytes here");
        e.put("normalized_result", "pass");
        return e; // timestamp intentionally omitted -> must be auto-filled
    }

    public static void main(String[] args) throws Exception {
        Path root = Path.of(System.getProperty("trinetra.root"));
        System.out.println("=== TrinetraNormalizedResultsTest ===");
        System.out.println("root: " + root + "\n");

        // ── Prepare a scored session via the real lifecycle API ──
        String name = "nrt_test";
        TrinetraSession.createSession(name, "127.0.0.1");

        // Simulate a completed scoring run so latest_score exists
        // (in production TrinetraBrain writes this field).
        Path statePath = TrinetraCommon.sessionBrainState(name);
        Map<String, Object> state = TrinetraCommon.readJsonFile(statePath);
        state.put("state", TrinetraSession.State.BRAIN_UPDATED.value);
        state.put("latest_score", TrinetraCommon.mapOf(
            "score", "85", "scored_at", TrinetraCommon.nowIso()));
        TrinetraCommon.writeJsonFile(statePath, state);

        // ── (a) Append + persist ────────────────────────────────
        System.out.println("(a) append entry and verify persistence");
        boolean ok = TrinetraSession.appendNormalizedResult(name, sampleEntry("dev-1"));
        expect(ok, "appendNormalizedResult returns true");
        ok = TrinetraSession.appendNormalizedResult(name, sampleEntry("dev-2"));
        expect(ok, "second appendNormalizedResult returns true");

        Map<String, Object> reloaded = TrinetraCommon.readJsonFile(statePath);
        List<Map<String, Object>> results =
            TrinetraCommon.getList(reloaded, TrinetraSession.NORMALIZED_RESULTS_FIELD);
        expect(results.size() == 2,
            "normalized_results persisted with 2 entries (got " + results.size() + ")");

        boolean allKeysPresent = true;
        boolean timestampsFilled = true;
        Set<String> ids = new HashSet<>();
        for (Map<String, Object> r : results) {
            for (String k : List.of("device_id", "vendor", "test_id",
                                    "raw_output", "normalized_result", "timestamp")) {
                if (!r.containsKey(k)) allKeysPresent = false;
            }
            Object ts = r.get("timestamp");
            if (!(ts instanceof String) || ((String) ts).isBlank()) timestampsFilled = false;
            ids.add(String.valueOf(r.get("device_id")));
        }
        expect(allKeysPresent, "every entry has all six schema keys");
        expect(timestampsFilled, "missing timestamps were auto-filled");
        expect(ids.equals(Set.of("dev-1", "dev-2")), "entry payloads round-trip intact");
        expect(TrinetraSession.getNormalizedResults(name).size() == 2,
            "getNormalizedResults reads back the same array");

        // ── (b) 14 required fields untouched and valid ──────────
        System.out.println("\n(b) required fields intact after append");
        List<String> errors = TrinetraSession.validateBrainState(name);
        expect(errors.isEmpty(),
            "validateBrainState clean after append" +
            (errors.isEmpty() ? "" : " -> " + errors));
        boolean allRequired = true;
        for (String f : REQUIRED_14) {
            if (!reloaded.containsKey(f)) {
                allRequired = false;
                System.err.println("    missing after append: " + f);
            }
        }
        expect(allRequired && REQUIRED_14.size() == 14,
            "all 14 required fields still present");
        expect(reloaded.get("session_name").equals(name)
               && reloaded.get("target").equals("127.0.0.1"),
            "field values not clobbered by append");

        // ── (c) Legacy file without the field ───────────────────
        System.out.println("\n(c) legacy brain-state file without normalized_results");
        String legacy = "nrt_legacy";
        Files.createDirectories(TrinetraCommon.sessionDir(legacy));
        Path legacyState = TrinetraCommon.sessionBrainState(legacy);
        StringBuilder old = new StringBuilder();
        old.append("{\n")
           .append("  \"session_name\": \"").append(legacy).append("\",\n")
           .append("  \"target\": \"192.168.1.0/24\",\n")
           .append("  \"state\": \"brain_updated\",\n")
           .append("  \"last_updated\": \"2026-07-01T00:00:00Z\",\n")
           .append("  \"byte_size\": 100,\n")
           .append("  \"estimated_tokens\": 25,\n")
           .append("  \"compression_count\": 0,\n")
           .append("  \"already_run_v_codes\": [],\n")
           .append("  \"confirmed_findings\": [],\n")
           .append("  \"suspected_findings\": [],\n")
           .append("  \"counts\": {\"total_runs\":\"0\",\"success_runs\":\"0\",")
           .append("\"failed_runs\":\"0\",\"unsummarized\":\"0\"},\n")
           .append("  \"latest_suggestion\": null,\n")
           .append("  \"suggestion_history\": [],\n")
           .append("  \"latest_score\": {\"score\": \"72\"}\n")
           .append("}\n");
        TrinetraCommon.writeFile(legacyState, old.toString());

        List<String> legacyErrors = TrinetraSession.validateBrainState(legacy);
        expect(legacyErrors.isEmpty(),
            "old file validates without error" +
            (legacyErrors.isEmpty() ? "" : " -> " + legacyErrors));
        expect(TrinetraSession.getNormalizedResults(legacy).isEmpty(),
            "missing normalized_results treated as empty array");

        // Appending into a legacy file must also work and stay valid.
        expect(TrinetraSession.appendNormalizedResult(legacy, sampleEntry("dev-9")),
            "append works on legacy file");
        expect(TrinetraSession.validateBrainState(legacy).isEmpty(),
            "legacy file valid after first append");

        // Bonus: pre-latest_score legacy file (like demo/ses27_07_26) must
        // report ONLY the known latest_score error, nothing about
        // normalized_results.
        String oldest = "nrt_oldest";
        Files.createDirectories(TrinetraCommon.sessionDir(oldest));
        Path oldestState = TrinetraCommon.sessionBrainState(oldest);
        TrinetraCommon.writeFile(oldestState, buildOldestJson());
        List<String> oldestErrors = TrinetraSession.validateBrainState(oldest);
        expect(oldestErrors.size() == 1
               && oldestErrors.get(0).contains("latest_score"),
            "pre-score file reports only known latest_score error -> "
            + oldestErrors);

        // ── (d) Hash chaining ───────────────────────────────────
        System.out.println("\n(d) hash chain: genesis, 3-link chain, tamper detection");
        testHashChaining(root);

        // ── (e) Concurrent writers (threads + separate processes) ──
        System.out.println("\n(e) concurrent writes: 8 threads + 4 JVM processes");
        testConcurrentWrites(root);

        System.out.println();
        if (failures == 0) {
            System.out.println("[+] TrinetraNormalizedResultsTest: all tests passed");
            return;
        }
        System.err.println("[-] TrinetraNormalizedResultsTest: " + failures + " failure(s)");
        System.exit(1);
    }

    /**
     * Both concurrency models seen in this codebase:
     *  - concurrent threads inside one JVM (in-process ReentrantLock),
     *  - concurrent `java` processes (cross-process FileChannel lock).
     * After all writers finish: no lost entries, verifyChain intact.
     */
    private static void testConcurrentWrites(Path root) throws Exception {
        String name = "nrt_conc";
        TrinetraSession.createSession(name, "10.0.1.1");
        Map<String, Object> st = TrinetraCommon.readJsonFile(
            TrinetraCommon.sessionBrainState(name));
        st.put("state", TrinetraSession.State.BRAIN_UPDATED.value);
        st.put("latest_score", TrinetraCommon.mapOf("score", "50"));
        TrinetraCommon.writeJsonFile(TrinetraCommon.sessionBrainState(name), st);

        final int THREADS = 8, PER_THREAD = 5, PROCS = 4, PER_PROC = 5;
        final int expectedTotal = THREADS * PER_THREAD + PROCS * PER_PROC;

        // (i) threads within this JVM
        java.util.concurrent.ExecutorService pool =
            java.util.concurrent.Executors.newFixedThreadPool(THREADS);
        java.util.concurrent.CountDownLatch go =
            new java.util.concurrent.CountDownLatch(1);
        List<java.util.concurrent.Future<Integer>> futures = new ArrayList<>();
        for (int t = 0; t < THREADS; t++) {
            final String tag = "t" + t;
            futures.add(pool.submit(() -> {
                go.await();
                int ok = 0;
                for (int i = 0; i < PER_THREAD; i++) {
                    Map<String, Object> e = new LinkedHashMap<>();
                    e.put("device_id", "dev-" + tag + "-" + i);
                    e.put("vendor", "Cisco");
                    e.put("test_id", "V-003");
                    e.put("raw_output", "thread write " + tag + " " + i);
                    e.put("normalized_result", "pass");
                    e.put("timestamp", "2026-08-22T11:00:00Z");
                    if (TrinetraSession.appendNormalizedResult(name, e)) ok++;
                }
                return ok;
            }));
        }
        go.countDown();
        int threadOk = 0;
        for (var f : futures) threadOk += f.get();
        pool.shutdown();
        expect(pool.awaitTermination(60, java.util.concurrent.TimeUnit.SECONDS),
            "thread pool drained");
        expect(threadOk == THREADS * PER_THREAD,
            "threads: all appends reported success (" + threadOk + "/"
            + (THREADS * PER_THREAD) + ")");

        // (ii) separate OS processes, each its own JVM
        Path outCp = Paths.get(System.getProperty("java.class.path"))
                          .toAbsolutePath();
        String javaBin = ProcessHandle.current()
                                      .info()
                                      .command()
                                      .orElse("java");
        List<Process> procs = new ArrayList<>();
        for (int w = 0; w < PROCS; w++) {
            String tag = "p" + w;
            ProcessBuilder pb = new ProcessBuilder(
                javaBin, "-Dtrinetra.root=" + root.toAbsolutePath(),
                "-cp", outCp.toString(),
                "TrinetraChainStressWorker", name, tag,
                String.valueOf(PER_PROC));
            pb.inheritIO();
            procs.add(pb.start());
        }
        int procOk = 0;
        for (Process p : procs) {
            expect(p.waitFor() == 0, "stress worker process exited 0");
            procOk += PER_PROC;
        }
        expect(procOk == PROCS * PER_PROC,
            "processes: all appends reported success (" + procOk
            + "/" + (PROCS * PER_PROC) + ")");

        // Verify: nothing lost, chain unbroken.
        int actual = TrinetraSession.getNormalizedResults(name).size();
        expect(actual == expectedTotal,
            "no entries lost: expected " + expectedTotal
            + ", found " + actual);

        TrinetraSession.ChainVerifyResult v = TrinetraSession.verifyChain(name);
        expect(v.intact && v.brokenAtIndex == -1,
            "verifyChain intact after concurrent writes -> " + v);
    }

    /** Genesis handling, multi-link integrity, and break-point detection. */
    private static void testHashChaining(Path root) throws Exception {
        String genesis = TrinetraSession.sha256Hex("TRINETRA_GENESIS");

        // Brand-new session: first entry must chain from the genesis hash.
        String name = "nrt_chain";
        TrinetraSession.createSession(name, "10.0.0.99");
        Map<String, Object> st = TrinetraCommon.readJsonFile(
            TrinetraCommon.sessionBrainState(name));
        st.put("state", TrinetraSession.State.BRAIN_UPDATED.value);
        st.put("latest_score", TrinetraCommon.mapOf("score", "50"));
        TrinetraCommon.writeJsonFile(TrinetraCommon.sessionBrainState(name), st);

        Map<String, Object> first = sampleEntry("dev-c1");
        first.put("timestamp", "2026-08-22T10:00:00Z");   // fixed for determinism
        expect(TrinetraSession.appendNormalizedResult(name, first),
            "chain session append #1");

        String expectedFirst =
            TrinetraSession.sha256Hex(genesis + TrinetraSession.canonicalJson(first));
        Map<String, Object> reloaded = TrinetraCommon.readJsonFile(
            TrinetraCommon.sessionBrainState(name));
        List<Map<String, Object>> links = TrinetraCommon.getList(
            reloaded, TrinetraSession.NORMALIZED_RESULTS_FIELD);
        expect(links.size() == 1, "one link present after genesis append");
        expect(expectedFirst.equals(links.get(0).get("chain_hash")),
            "first entry hash = SHA256(genesis + canonical(entry))");

        // Two more appends build a 3-link chain.
        Map<String, Object> second = sampleEntry("dev-c2");
        second.put("timestamp", "2026-08-22T10:01:00Z");
        Map<String, Object> third = sampleEntry("dev-c3");
        third.put("timestamp", "2026-08-22T10:02:00Z");
        expect(TrinetraSession.appendNormalizedResult(name, second), "append #2");
        expect(TrinetraSession.appendNormalizedResult(name, third), "append #3");

        reloaded = TrinetraCommon.readJsonFile(TrinetraCommon.sessionBrainState(name));
        links = TrinetraCommon.getList(reloaded, TrinetraSession.NORMALIZED_RESULTS_FIELD);
        expect(links.size() == 3, "three links persisted");

        // Running tracker references the tip without a full re-walk.
        String tip = (String) links.get(2).get("chain_hash");
        expect(tip.equals(reloaded.get(TrinetraSession.PREVIOUS_CHAIN_HASH_FIELD)),
            "previous_chain_hash tracker equals last entry's hash");

        TrinetraSession.ChainVerifyResult v = TrinetraSession.verifyChain(name);
        expect(v.intact && v.brokenAtIndex == -1,
            "verifyChain intact on 3-link chain -> " + v);

        // Global snapshot chain: created via refreshGlobalBrainState during
        // createSession; must verify intact.
        TrinetraSession.ChainVerifyResult g = TrinetraSession.verifyGlobalChain();
        expect(g.intact, "verifyGlobalChain intact -> " + g);

        // Tamper: rewrite entry [1]'s content WITHOUT updating any hash.
        links.get(1).put("normalized_result", "TAMPERED");
        reloaded.put(TrinetraSession.NORMALIZED_RESULTS_FIELD, links);
        TrinetraCommon.writeJsonFile(TrinetraCommon.sessionBrainState(name), reloaded);

        TrinetraSession.ChainVerifyResult broken = TrinetraSession.verifyChain(name);
        expect(!broken.intact, "verifyChain detects tampering");
        expect(broken.brokenAtIndex == 1,
            "break point is exactly entry index 1 -> " + broken);
    }

    /** Old-format file: 13 fields, no latest_score, no normalized_results. */
    private static String buildOldestJson() {
        return "{\n"
            + "  \"session_name\": \"nrt_oldest\",\n"
            + "  \"target\": \"10.0.0.1\",\n"
            + "  \"state\": \"brain_updated\",\n"
            + "  \"last_updated\": \"2026-06-01T00:00:00Z\",\n"
            + "  \"byte_size\": 10,\n"
            + "  \"estimated_tokens\": 3,\n"
            + "  \"compression_count\": 0,\n"
            + "  \"already_run_v_codes\": [],\n"
            + "  \"confirmed_findings\": [],\n"
            + "  \"suspected_findings\": [],\n"
            + "  \"counts\": {\"total_runs\":\"0\",\"success_runs\":\"0\","
            + "\"failed_runs\":\"0\",\"unsummarized\":\"0\"},\n"
            + "  \"latest_suggestion\": null,\n"
            + "  \"suggestion_history\": []\n"
            + "}\n";
    }
}
