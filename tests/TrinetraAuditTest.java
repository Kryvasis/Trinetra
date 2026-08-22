import java.nio.file.*;
import java.sql.*;
import java.util.*;

/**
 * Tests for the TrinetraAudit SQLite append-only audit log (Prompt 11).
 *
 * Covers:
 *  (a) no --user flag  -> falls back to the OS username,
 *  (b) --user / -u     -> provided value is used and stripped from args,
 *  (c) multiple actions in one run share a single audit_uuid,
 *  (d) source-level check: no UPDATE/DELETE/DROP/ALTER capability exists
 *      anywhere in the audit write path; INSERT is the only mutation,
 *  (e) session_end row links back to the brain-state chain hash.
 *
 * Run via `make test-java` (temp trinetra.root + lib/* on classpath).
 */
public class TrinetraAuditTest {

    private static int failures = 0;

    private static void expect(boolean cond, String what) {
        if (cond) {
            System.out.println("  [ok] " + what);
        } else {
            System.err.println("  [FAIL] " + what);
            failures++;
        }
    }

    public static void main(String[] args) throws Exception {
        Path root = Path.of(System.getProperty("trinetra.root"));
        System.out.println("=== TrinetraAuditTest ===");
        System.out.println("root: " + root);
        System.out.println("db:   " + TrinetraAudit.DB_PATH + "\n");

        // ── (a) OS username fallback ────────────────────────────
        System.out.println("(a) missing --user falls back to OS username");
        List<String> argv = new ArrayList<>(List.of("-new", "s1", "10.0.0.1"));
        String osUser = Trinetra.extractUserId(argv);
        expect(osUser.equals(System.getProperty("user.name")),
            "fallback user == user.name (" + osUser + ")");
        expect(argv.size() == 3, "argv untouched when flag absent");

        // ── (b) explicit --user / -u wins and is stripped ───────
        System.out.println("\n(b) explicit --user / -u value is used");
        argv = new ArrayList<>(List.of("--user", "alice", "-new", "s2", "10.0.0.2"));
        String alice = Trinetra.extractUserId(argv);
        expect("alice".equals(alice), "--user long form -> alice");
        expect(!argv.contains("alice") && !argv.contains("--user"),
            "flag pair stripped from argv");
        argv = new ArrayList<>(List.of("-u", "bob", "-pen"));
        expect("bob".equals(Trinetra.extractUserId(argv)), "-u short form -> bob");
        expect(argv.size() == 1 && argv.get(0).equals("-pen"), "only -pen remains");

        // ── (c) one run -> one uuid across multiple rows ────────
        System.out.println("\n(c) multiple actions share one audit_uuid");
        TrinetraAudit.beginNewRun();
        String uuid = TrinetraAudit.currentRunUuid();
        expect(uuid != null && uuid.matches("[0-9a-f-]{36}"), "run uuid is a UUID");
        boolean w1 = TrinetraAudit.log("alice", "session_start", "audit_s", null, "target=x");
        boolean w2 = TrinetraAudit.log("alice", "test_executed", "audit_s", null, "test=V-003, status=success");
        boolean w3 = TrinetraAudit.log("alice", "test_executed", "audit_s", null, "test=V-006, status=failed");
        expect(w1 && w2 && w3, "three inserts succeeded");

        try (Connection c = openDb();
             PreparedStatement ps = c.prepareStatement(
                 "SELECT action, count(*) FROM audit_log WHERE audit_uuid = ? GROUP BY action")) {
            ps.setString(1, uuid);
            Map<String, Integer> byAction = new LinkedHashMap<>();
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) byAction.put(rs.getString(1), rs.getInt(2));
            }
            expect(byAction.size() == 2, "two distinct actions under this uuid");
            expect(Integer.valueOf(1).equals(byAction.get("session_start"))
                   && Integer.valueOf(2).equals(byAction.get("test_executed")),
                "row counts per action correct -> " + byAction);
        }
        try (Connection c = openDb();
             Statement st = c.createStatement();
             ResultSet rs = st.executeQuery(
                 "SELECT count(DISTINCT audit_uuid) FROM audit_log WHERE user_id='alice'")) {
            rs.next();
            expect(rs.getInt(1) == 1, "single audit_uuid for all alice rows");
        }

        // ── (d) append-only enforcement at source level ─────────
        System.out.println("\n(d) no update/delete/drop/alter in the audit code path");
        Path src = locateSource("TrinetraAudit.java");
        String code = Files.readString(src);
        java.util.regex.Matcher m = java.util.regex.Pattern.compile(
            "(?i)(update|delete\\s+from|drop\\s+table|alter\\s+table)")
            .matcher(code);
        List<String> hits = new ArrayList<>();
        while (m.find()) hits.add(m.group());
        expect(hits.isEmpty(), "no mutating SQL keywords in TrinetraAudit.java"
            + (hits.isEmpty() ? "" : " -> " + hits));
        expect(countOccurrences(code, "INSERT INTO") == 1,
            "exactly one INSERT statement (single write path)");
        expect(code.contains("SELECT"), "read-back SELECTs are present");
        expect(code.contains(".execute();") && !code.contains("executeUpdate")
               && !code.contains("executeDelete") && !code.contains("executeBatch"),
            "JDBC calls limited to non-mutating execute() forms");

        // ── (e) session_end captures brain-state chain hash ─────
        System.out.println("\n(e) session_end links back to chain_hash");
        TrinetraSession.createSession("nrt_audit_e", "127.0.0.9");
        Map<String, Object> e1 = new LinkedHashMap<>();
        e1.put("device_id", "dev-a"); e1.put("vendor", "Cisco");
        e1.put("test_id", "V-003");   e1.put("raw_output", "r");
        e1.put("normalized_result", "pass"); e1.put("timestamp", "2026-08-22T00:00:00Z");
        Map<String, Object> e2 = new LinkedHashMap<>(e1);
        e2.put("device_id", "dev-b");
        TrinetraSession.appendNormalizedResult("nrt_audit_e", e1);
        TrinetraSession.appendNormalizedResult("nrt_audit_e", e2);

        TrinetraAudit.beginNewRun();
        TrinetraAudit.sessionEnd("bob", "nrt_audit_e", "report generated, cert=default");

        String expectedTip = TrinetraSession.getLatestChainHash("nrt_audit_e");
        try (Connection c = openDb();
             PreparedStatement ps = c.prepareStatement(
                 "SELECT final_chain_hash, details FROM audit_log "
                 + "WHERE session_name = 'nrt_audit_e' AND action = 'session_end'")) {
            try (ResultSet rs = ps.executeQuery()) {
                boolean row = rs.next();
                expect(row, "session_end row exists for nrt_audit_e");
                if (row) {
                    expect(expectedTip != null
                           && expectedTip.equals(rs.getString(1)),
                        "final_chain_hash matches brain-state tip");
                    expect(rs.getString(2).contains("cert=default"),
                        "completion detail recorded");
                }
            }
        }
        expect(TrinetraAudit.countRows(uuid) >= 3,
            "earlier run's rows still intact (append-only)");

        System.out.println();
        if (failures == 0) {
            System.out.println("[+] TrinetraAuditTest: all tests passed");
            return;
        }
        System.err.println("[-] TrinetraAuditTest: " + failures + " failure(s)");
        System.exit(1);
    }

    /**
     * Locate a src/ file relative to the compiled classes (out/ lives in
     * the project root), independent of the temp trinetra.root.
     */
    private static Path locateSource(String filename) throws Exception {
        Path outDir = Path.of(TrinetraAudit.class.getProtectionDomain()
            .getCodeSource().getLocation().toURI());
        return outDir.toAbsolutePath().getParent()
            .resolve("src").resolve(filename);
    }

    private static Connection openDb() throws Exception {
        Class.forName("org.sqlite.JDBC");
        return DriverManager.getConnection(
            "jdbc:sqlite:" + TrinetraAudit.DB_PATH.toAbsolutePath());
    }

    private static int countOccurrences(String haystack, String needle) {
        int n = 0, idx = 0;
        while ((idx = haystack.indexOf(needle, idx)) >= 0) { n++; idx += needle.length(); }
        return n;
    }
}
