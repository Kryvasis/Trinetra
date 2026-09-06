import java.nio.file.*;
import java.util.*;

/**
 * Bridge helper — minimal Java entry for Flask bridge.
 * Provides:
 *   status <session>        -> JSON with chain verification + session metadata
 *   set-vendor <session> <device_id> <vendor> -> sets device_vendors mapping
 *
 * Keeps Java as source of truth; Python only shells out.
 */
public class TrinetraBridgeHelper {
    public static void main(String[] args) {
        if (args.length == 0) {
            System.err.println("Usage: TrinetraBridgeHelper <status|set-vendor|ingest-config|get-unrecognized> ...");
            System.exit(1);
        }
        String cmd = args[0];
        try {
            switch (cmd) {
                case "status":
                    handleStatus(args);
                    break;
                case "remove-device":
                case "restore-device":
                    if (args.length != 3 || !args[1].matches("[A-Za-z0-9_-]{1,64}")
                        || !args[2].matches("[A-Za-z0-9._-]{1,128}"))
                        throw new IllegalArgumentException("Invalid session or device identifier");
                    if (!TrinetraSession.setDeviceRemoved(args[1], args[2], cmd.equals("remove-device"))) {
                        System.err.println("Session or device not found");
                        System.exit(2);
                    }
                    System.out.println("{\"status\":\"ok\"}");
                    break;
                case "set-vendor":
                    handleSetVendor(args);
                    break;
                case "ingest-config":
                    handleIngestConfig(args);
                    break;
                case "get-unrecognized":
                    handleGetUnrecognized(args);
                    break;
                default:
                    System.err.println("Unknown command: " + cmd);
                    System.exit(1);
            }
        } catch (Exception e) {
            System.err.println("Bridge helper error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static void handleStatus(String[] args) {
        if (args.length < 2) {
            System.err.println("Usage: TrinetraBridgeHelper status <session>");
            System.exit(1);
        }
        String session = args[1];
        String sanitized = TrinetraCommon.sanitizeName(session);

        // Verify session exists
        Map<String, Object> sess = TrinetraSession.loadSession(sanitized);
        if (sess == null || sess.isEmpty()) {
            System.err.println("Session not found: " + session);
            System.exit(2);
        }

        // Chain verification
        TrinetraSession.ChainVerifyResult chain = TrinetraSession.verifyChain(sanitized);
        TrinetraSession.ChainVerifyResult global = TrinetraSession.verifyGlobalChain();

        // Session metadata
        String target = TrinetraCommon.getString(sess, "target", "unknown");
        String createdAt = TrinetraCommon.getString(sess, "created_at", "");
        String updatedAt = TrinetraCommon.getString(sess, "updated_at", "");
        String status = TrinetraCommon.getString(sess, "status", "unknown");

        // Brain state
        Map<String, Object> brainState = TrinetraCommon.readJsonFile(TrinetraCommon.sessionBrainState(sanitized));
        List<Map<String, Object>> nr = TrinetraSession.getNormalizedResults(sanitized);
        String chainHash = TrinetraSession.getLatestChainHash(sanitized);
        Map<String, String> deviceVendors = TrinetraSession.getAllDeviceVendors(sanitized);

        // Build response
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("session_name", sanitized);
        out.put("original_session_name", session);
        out.put("target", target);
        out.put("status", status);
        out.put("created_at", createdAt);
        out.put("updated_at", updatedAt);
        out.put("chain", Map.of(
            "intact", chain.intact,
            "brokenAtIndex", chain.brokenAtIndex,
            "detail", chain.detail,
            "linkCount", nr.size(),
            "latestHash", chainHash != null ? chainHash : ""
        ));
        out.put("global_chain", Map.of(
            "intact", global.intact,
            "detail", global.detail
        ));
        out.put("normalized_results_count", nr.size());
        out.put("device_vendors", deviceVendors);
        out.put("device_ingestion", TrinetraSession.getAllDeviceIngestion(sanitized));
        out.put("device_details", TrinetraSession.getAllDeviceDetails(sanitized));
        out.put("unrecognized_by_device", TrinetraSession.getAllUnrecognizedLines(sanitized));
        out.put("evidence_count", TrinetraEvidence.count(sanitized));
        out.put("evidence_json", "evidence_" + sanitized + ".json");
        out.put("evidence_md", "evidence_" + sanitized + ".md");
        out.put("brain_state_exists", !brainState.isEmpty());
        if (!brainState.isEmpty()) {
            out.put("brain_state_last_updated", TrinetraCommon.getString(brainState, "last_updated", ""));
            out.put("brain_state_state", TrinetraCommon.getString(brainState, "state", ""));
        }
        // Validation
        List<String> sessErrors = TrinetraSession.validateSession(sanitized);
        List<String> brainErrors = TrinetraSession.validateBrainState(sanitized);
        out.put("validation", Map.of(
            "session_errors", sessErrors,
            "brain_state_errors", brainErrors,
            "valid", sessErrors.isEmpty() && brainErrors.isEmpty()
        ));

        System.out.println(TrinetraJson.prettyJson(out));
    }

    private static void handleSetVendor(String[] args) {
        if (args.length < 4) {
            System.err.println("Usage: TrinetraBridgeHelper set-vendor <session> <device_id> <vendor>");
            System.exit(1);
        }
        String session = args[1];
        String deviceId = args[2];
        String vendor = args[3];
        boolean ok = TrinetraSession.setDeviceVendor(session, deviceId, vendor);
        if (!ok) {
            System.err.println("Failed to set device vendor for session " + session);
            System.exit(1);
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("session", TrinetraCommon.sanitizeName(session));
        out.put("device_id", deviceId);
        out.put("vendor", vendor);
        out.put("status", "ok");
        System.out.println(TrinetraJson.prettyJson(out));
    }

    private static void handleIngestConfig(String[] args) {
        if (args.length < 5) {
            System.err.println("Usage: TrinetraBridgeHelper ingest-config <session> <device_id> <vendor> <config_file_path> [serial] [hardware_model] [os_version] [ingestion_method]");
            System.exit(1);
        }
        String session = args[1];
        String deviceId = args[2];
        String vendor = args[3];
        String configPath = args[4];
        String serialNumber = args.length > 5 ? args[5] : null;
        String hardwareModel = args.length > 6 ? args[6] : null;
        String osVersion = args.length > 7 ? args[7] : null;
        String ingestionMethod = args.length > 8 ? args[8] : "config_upload";
        // Decode "_" placeholder used for empty optional fields
        if ("_".equals(serialNumber)) serialNumber = "";
        if ("_".equals(hardwareModel)) hardwareModel = "";
        if ("_".equals(osVersion)) osVersion = "";
        if (ingestionMethod == null || ingestionMethod.isBlank() || "_".equals(ingestionMethod)) {
            ingestionMethod = "config_upload";
        }
        String configContent = TrinetraCommon.readFileIfExists(Path.of(configPath));
        if (configContent == null) {
            System.err.println("Config file not found: " + configPath);
            System.exit(1);
        }
        // Defense in depth: reject HTML/web documents before ingestion (mirrors bridge/config_validation)
        if (looksLikeHtml(configContent)) {
            System.err.println("Webpages are not device configurations. This is a webpage, not a device configuration. Use Website analysis for public URLs, or provide a real device configuration export.");
            System.exit(2);
        }
        // Additional config sanity: reject content that is overwhelmingly non-config (e.g. JS error pages)
        if (!isPlausibleConfig(configContent)) {
            System.err.println("Fetched content does not appear to be a device configuration — check the target and try again.");
            System.exit(2);
        }
        String filename = Path.of(configPath).getFileName().toString();
        TrinetraConfigIngestor.IngestResult result = TrinetraConfigIngestor.ingest(
            session, deviceId, vendor, configContent, filename,
            serialNumber, hardwareModel, osVersion, ingestionMethod);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("session", TrinetraCommon.sanitizeName(session));
        out.put("device_id", result.deviceId);
        out.put("vendor", result.vendor);
        out.put("ingestion_method", result.ingestionMethod);
        out.put("total_checks", result.totalChecks);
        out.put("passed", result.passed);
        out.put("failed", result.failed);
        out.put("unrecognized_lines", result.unrecognizedLines);
        out.put("unrecognized_count", result.unrecognizedLines.size());
        out.put("status", "ok");
        System.out.println(TrinetraJson.prettyJson(out));
    }

    private static void handleGetUnrecognized(String[] args) {
        if (args.length < 2) {
            System.err.println("Usage: TrinetraBridgeHelper get-unrecognized <session> [device_id]");
            System.exit(1);
        }
        String session = args[1];
        String sanitized = TrinetraCommon.sanitizeName(session);
        Map<String, Object> sess = TrinetraSession.loadSession(sanitized);
        if (sess == null || sess.isEmpty()) {
            System.err.println("Session not found: " + session);
            System.exit(2);
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("session", sanitized);
        if (args.length >= 3) {
            String deviceId = args[2];
            List<String> lines = TrinetraSession.getRemovedDevices(sanitized).contains(deviceId)
                ? List.of() : TrinetraSession.getUnrecognizedLines(sanitized, deviceId);
            out.put("device_id", deviceId);
            out.put("unrecognized_lines", lines);
            out.put("count", lines.size());
        } else {
            Map<String, List<String>> all = new LinkedHashMap<>(TrinetraSession.getAllUnrecognizedLines(sanitized));
            TrinetraSession.getRemovedDevices(sanitized).forEach(all::remove);
            out.put("unrecognized_by_device", all);
            int total = 0;
            for (List<String> l : all.values()) total += l.size();
            out.put("total_unrecognized", total);
        }
        // Also include device ingestion map + details for context
        out.put("device_ingestion", TrinetraSession.getAllDeviceIngestion(sanitized));
        out.put("device_vendors", TrinetraSession.getAllDeviceVendors(sanitized));
        out.put("device_details", TrinetraSession.getAllDeviceDetails(sanitized));
        System.out.println(TrinetraJson.prettyJson(out));
    }

    // ── Content sanity (mirrors bridge/config_validation.py) ──
    private static boolean looksLikeHtml(String content) {
        if (content == null || content.isBlank()) return false;
        String head = content.length() > 65536 ? content.substring(0, 65536) : content;
        String lower = head.toLowerCase();
        if (lower.contains("<!doctype html") || lower.contains("<html") || lower.contains("<head") || lower.contains("<body") || lower.contains("<script")) return true;
        if (lower.contains("window.ytcfg") || lower.contains("emergency_base_url") || lower.contains("ytinitialdata")) return true;
        String stripped = head.strip();
        if (stripped.startsWith("{") && stripped.toLowerCase().contains("\"error\"")) {
            // JSON error response
            if (stripped.contains("{") && stripped.contains("}") && stripped.length() < 5000) return true;
        }
        return false;
    }

    private static boolean isPlausibleConfig(String content) {
        if (content == null || content.isBlank()) return false;
        if (content.contains("\u0000")) return false;
        if (looksLikeHtml(content)) return false;
        String lowerHead = content.length() > 4096 ? content.substring(0, 4096).toLowerCase() : content.toLowerCase();
        if ((lowerHead.contains("404 not found") || lowerHead.contains("500 internal server error") || lowerHead.contains("error_204")) && configLikenessRatio(content) < 0.30) {
            return false;
        }
        String[] lines = content.split("\\r?\\n");
        int nonEmpty = 0;
        for (String l : lines) if (!l.trim().isEmpty()) nonEmpty++;
        if (nonEmpty >= 5) {
            double ratio = configLikenessRatio(content);
            if (ratio < 0.30) return false;
        }
        return true;
    }

    private static double configLikenessRatio(String content) {
        if (content == null || content.isBlank()) return 0.0;
        if (content.contains("\u0000")) return 0.0;
        String[] rawLines = content.split("\\r?\\n");
        List<String> lines = new ArrayList<>();
        for (String l : rawLines) if (!l.trim().isEmpty()) lines.add(l);
        if (lines.isEmpty()) return 0.0;
        int configLike = 0;
        for (String line : lines) {
            String stripped = line.trim();
            if (stripped.contains("<") && stripped.contains(">")) continue;
            if (stripped.length() > 500) continue;
            // Config line shape: starts with alphanum/!/# and contains typical CLI tokens
            if (line.matches("(?i)^\\s*(?:[!#].*|[A-Za-z0-9][\\w\\-\\./:]*(\\s+[\\w\\-\\./:,\\[\\]{};='\"\\(\\)]+)*)\\s*$")) {
                configLike++;
            }
        }
        return (double) configLike / lines.size();
    }
}
