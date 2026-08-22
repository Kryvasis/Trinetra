import java.util.*;

/**
 * Stress worker for TrinetraNormalizedResultsTest concurrency checks.
 * Runs as a SEPARATE OS process (its own JVM) so that cross-process
 * FileChannel locking around brain-state writes is exercised.
 *
 * Usage: java -Dtrinetra.root=<root> -cp out TrinetraChainStressWorker \
 *            <session> <tag> <count>
 * Appends <count> normalized_results entries tagged dev-<tag>-<i>.
 * Exits 0 only if every append succeeded.
 */
public class TrinetraChainStressWorker {
    public static void main(String[] args) throws Exception {
        String session = args[0];
        String tag = args[1];
        int count = Integer.parseInt(args[2]);

        int ok = 0;
        for (int i = 0; i < count; i++) {
            Map<String, Object> e = new LinkedHashMap<>();
            e.put("device_id", "dev-" + tag + "-" + i);
            e.put("vendor", "Cisco");
            e.put("test_id", "V-003");
            e.put("raw_output", "stress " + tag + " " + i);
            e.put("normalized_result", "pass");
            e.put("timestamp", String.format("2026-08-22T12:%02d:%02dZ", i / 60, i % 60));
            if (TrinetraSession.appendNormalizedResult(session, e)) ok++;
        }
        System.out.println("worker " + tag + " appended " + ok + "/" + count);
        System.exit(ok == count ? 0 : 1);
    }
}
