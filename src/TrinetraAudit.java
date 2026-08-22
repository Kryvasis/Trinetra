import java.nio.file.*;
import java.sql.*;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Local append-only audit log (SQLite).
 *
 * One row per significant action (session start, test executed,
 * session end/report generated).  Rows carry a per-run audit_uuid
 * linking all actions of one CLI invocation, and session-completion
 * rows capture the brain-state chain_hash so the SQLite log links
 * back to the tamper-evident chain for that session.
 *
 * Append-only by construction: the only SQL statements in this file
 * are CREATE TABLE IF NOT EXISTS, INSERT, and SELECT.  No row- or
 * schema-modification statements exist in this module, and no other
 * class writes to this table.  TrinetraAuditTest enforces this at
 * source level by rejecting any occurrence of those keywords.
 */
public class TrinetraAudit {

    public static final Path DB_PATH =
        Path.of(TrinetraCommon.PROJECT_ROOT, "trinetra_audit.db");

    private static final ReentrantLock WRITE_LOCK = new ReentrantLock();
    private static volatile String runUuid;
    private static volatile boolean schemaReady;
    private static volatile boolean driverMissingLogged;

    private TrinetraAudit() {}

    /** UUID of the current audit run; created lazily once per invocation. */
    public static synchronized String currentRunUuid() {
        if (runUuid == null || runUuid.isBlank()) beginNewRun();
        return runUuid;
    }

    /** Start a fresh audit run (new CLI invocation / test scenario). */
    public static synchronized void beginNewRun() {
        runUuid = java.util.UUID.randomUUID().toString();
        schemaReady = false;
    }

    /**
     * The single write path into audit_log.  INSERT only.
     *
     * @return true when the row was persisted; false when the driver is
     *         unavailable or the write failed (auditing never blocks the
     *         tool — failures are logged and skipped).
     */
    public static boolean log(String userId, String action, String sessionName,
                              String finalChainHash, String details) {
        WRITE_LOCK.lock();
        try {
            try (Connection c = connect()) {
                if (!schemaReady) ensureSchema(c);
                try (PreparedStatement ps = c.prepareStatement(
                    "INSERT INTO audit_log "
                    + "(audit_uuid, user_id, timestamp, action, session_name, "
                    + " final_chain_hash, details) VALUES (?,?,?,?,?,?,?)")) {
                    ps.setString(1, currentRunUuid());
                    ps.setString(2, userId);
                    ps.setString(3, TrinetraCommon.nowIso());
                    ps.setString(4, action);
                    ps.setString(5, sessionName);
                    ps.setString(6, finalChainHash);
                    ps.setString(7, details);
                    ps.execute();
                    return true;
                }
            }
        } catch (SQLException e) {
            if (!driverMissingLogged) {
                TrinetraCommon.logWarn("Audit log unavailable: "
                    + e.getMessage());
                driverMissingLogged = true;
            }
            return false;
        } finally {
            WRITE_LOCK.unlock();
        }
    }

    // ── Significant-action helpers used by the CLI layer ──

    public static void sessionStart(String userId, String session, String target) {
        log(userId, "session_start", session, null, "target=" + target);
    }

    public static void testExecuted(String userId, String session,
                                    String vCode, String status) {
        log(userId, "test_executed", session, null,
            "test=" + vCode + ", status=" + status);
    }

    /**
     * Session completion (report generated): captures the session's latest
     * known-good brain-state chain hash for cross-log linkage.
     */
    public static void sessionEnd(String userId, String session, String detail) {
        String sanitized = TrinetraCommon.sanitizeName(session);
        String chainHash = TrinetraSession.getLatestChainHash(sanitized);
        log(userId, "session_end", sanitized, chainHash, detail);
    }

    // ── Internals ──

    private static Connection connect() throws SQLException {
        try {
            Class.forName("org.sqlite.JDBC");
        } catch (ClassNotFoundException e) {
            throw new SQLException(
                "SQLite JDBC driver not on classpath (expected lib/sqlite-jdbc-*.jar)",
                e);
        }
        return DriverManager.getConnection(
            "jdbc:sqlite:" + DB_PATH.toAbsolutePath());
    }

    private static void ensureSchema(Connection c) throws SQLException {
        try (Statement st = c.createStatement()) {
            st.execute("CREATE TABLE IF NOT EXISTS audit_log ("
                + "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                + "audit_uuid TEXT NOT NULL, "
                + "user_id TEXT NOT NULL, "
                + "timestamp TEXT NOT NULL, "
                + "action TEXT NOT NULL, "
                + "session_name TEXT, "
                + "final_chain_hash TEXT, "
                + "details TEXT)");
        }
        schemaReady = true;
    }

    /** Row count for an audit run (read-back used by tests/diagnostics). */
    public static int countRows(String auditUuid) {
        WRITE_LOCK.lock();
        try (Connection c = connect()) {
            if (!schemaReady) ensureSchema(c);
            try (PreparedStatement ps = c.prepareStatement(
                "SELECT count(*) FROM audit_log WHERE audit_uuid = ?")) {
                ps.setString(1, auditUuid);
                try (ResultSet rs = ps.executeQuery()) {
                    return rs.next() ? rs.getInt(1) : 0;
                }
            }
        } catch (SQLException e) {
            TrinetraCommon.logWarn("Audit read failed: " + e.getMessage());
            return -1;
        } finally {
            WRITE_LOCK.unlock();
        }
    }
}
