import java.io.*;
import java.nio.file.*;
import java.time.*;
import java.time.format.*;
import java.util.*;
import java.util.concurrent.*;

/**
 * Shared utilities for Trinetra beta.
 * File IO, timestamps, shell execution, atomic writes, logging.
 */
public class TrinetraCommon {

    public static final String PROJECT_ROOT = System.getProperty("trinetra.root", resolveProjectRoot());
    public static final Path SESSIONS_DIR = Path.of(PROJECT_ROOT, "sessions");
    public static final Path HEX_SCRIPTS_DIR = Path.of(PROJECT_ROOT, "hex_scripts");
    public static final Path OUTPUT_DIR = Path.of(PROJECT_ROOT, "output");
    public static final Path GLOBAL_BRAIN_STATE = Path.of(PROJECT_ROOT, "brain_state.json");
    public static final Path HEXSTRIKE_DIR = Path.of(System.getProperty("user.home"), ".hexsrtike");

    public static final String BRAIN_COMPRESS_BYTE_THRESHOLD_KEY = "trinetra.brain.compress.bytes";
    public static final long BRAIN_COMPRESS_BYTE_DEFAULT = 50000;
    public static final String BRAIN_COMPRESS_TOKEN_THRESHOLD_KEY = "trinetra.brain.compress.tokens";
    public static final long BRAIN_COMPRESS_TOKEN_DEFAULT = 12000;

    private static final ExecutorService PACE_EXECUTOR = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "trinetra-pace");
        t.setDaemon(true);
        return t;
    });

    private static volatile long lastOpenRouterCall = 0;
    private static final long OPENROUTER_PACE_MS = 3000;

    static {
        try {
            Files.createDirectories(SESSIONS_DIR);
            Files.createDirectories(OUTPUT_DIR);
        } catch (IOException e) {
            System.err.println("[trinetra] Failed to create base directories: " + e.getMessage());
        }
    }

    private static String resolveProjectRoot() {
        String prop = System.getProperty("trinetra.root");
        if (prop != null) return prop;
        try {
            Path cwd = Path.of(System.getProperty("user.dir")).toAbsolutePath();
            if (cwd.endsWith("Trinetra_v") || cwd.endsWith("Trinetra")) return cwd.toString();
            return cwd.toString();
        } catch (Exception e) {
            return System.getProperty("user.dir");
        }
    }

    public static String nowIso() {
        return Instant.now().atZone(ZoneOffset.UTC).format(DateTimeFormatter.ISO_INSTANT);
    }

    public static String sanitizeName(String name) {
        return name.replaceAll("[^a-zA-Z0-9_\\-]", "_");
    }

    public static Path sessionDir(String session) {
        return SESSIONS_DIR.resolve(sanitizeName(session));
    }

    public static Path sessionJson(String session) {
        return sessionDir(session).resolve(sanitizeName(session) + ".json");
    }

    public static Path sessionBrainMd(String session) {
        return sessionDir(session).resolve("brain_" + sanitizeName(session) + ".md");
    }

    public static Path sessionBrainBackup(String session) {
        return sessionDir(session).resolve("brain_" + sanitizeName(session) + ".bak.md");
    }

    public static Path sessionBrainState(String session) {
        return sessionDir(session).resolve("brain_state_" + sanitizeName(session) + ".json");
    }

    public static Path sessionArtifactsDir(String session) {
        return sessionDir(session).resolve("artifacts");
    }

    public static String readFile(Path path) {
        try {
            return Files.exists(path) ? Files.readString(path) : null;
        } catch (IOException e) {
            log("ERROR", "Failed to read " + path + ": " + e.getMessage());
            return null;
        }
    }

    public static void writeFile(Path path, String content) {
        try {
            Files.createDirectories(path.getParent());
            Files.writeString(path, content);
        } catch (IOException e) {
            log("ERROR", "Failed to write " + path + ": " + e.getMessage());
        }
    }

    public static void atomicWriteFile(Path path, String content) {
        try {
            Files.createDirectories(path.getParent());
            Path tmp = path.resolveSibling(path.getFileName() + ".tmp");
            Files.writeString(tmp, content);
            Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException e) {
            try {
                Path tmp = path.resolveSibling(path.getFileName() + ".tmp");
                Files.writeString(tmp, content);
                Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException ex) {
                log("ERROR", "Atomic write failed for " + path + ": " + ex.getMessage());
            }
        } catch (IOException e) {
            log("ERROR", "Write failed for " + path + ": " + e.getMessage());
        }
    }

    public static String readFileIfExists(Path path) {
        try {
            return Files.exists(path) ? Files.readString(path) : null;
        } catch (IOException e) {
            return null;
        }
    }

    public static void appendToFile(Path path, String content) {
        try {
            Files.createDirectories(path.getParent());
            Files.writeString(path, content, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            log("ERROR", "Failed to append to " + path + ": " + e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> readJsonFile(Path path) {
        String content = readFile(path);
        if (content == null || content.isBlank()) return new LinkedHashMap<>();
        try {
            Object parsed = TrinetraJson.parse(content);
            if (parsed instanceof Map) return (Map<String, Object>) parsed;
        } catch (Exception e) {
            log("ERROR", "Failed to parse JSON from " + path + ": " + e.getMessage());
        }
        return new LinkedHashMap<>();
    }

    public static void writeJsonFile(Path path, Object data) {
        atomicWriteFile(path, TrinetraJson.prettyJson(data));
    }

    public static String[] execCommand(String... command) {
        return execCommand(30, command);
    }

    public static String[] execCommand(int timeoutSeconds, String... command) {
        Process proc = null;
        try {
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.redirectErrorStream(false);
            pb.environment().put("LC_ALL", "C");
            proc = pb.start();
            final Process finalProc = proc;

            StringBuilder stdout = new StringBuilder();
            StringBuilder stderr = new StringBuilder();

            Thread outThread = new Thread(() -> {
                try (BufferedReader br = new BufferedReader(new InputStreamReader(finalProc.getInputStream()))) {
                    String line;
                    while ((line = br.readLine()) != null) stdout.append(line).append("\n");
                } catch (IOException ignored) {}
            });
            Thread errThread = new Thread(() -> {
                try (BufferedReader br = new BufferedReader(new InputStreamReader(finalProc.getErrorStream()))) {
                    String line;
                    while ((line = br.readLine()) != null) stderr.append(line).append("\n");
                } catch (IOException ignored) {}
            });

            outThread.start();
            errThread.start();

            boolean finished = proc.waitFor(timeoutSeconds, TimeUnit.SECONDS);
            if (!finished) {
                proc.destroyForcibly();
                return new String[]{ "", "Command timed out after " + timeoutSeconds + "s", "-1" };
            }

            outThread.join(2000);
            errThread.join(2000);

            return new String[]{
                stdout.toString().strip(),
                stderr.toString().strip(),
                String.valueOf(proc.exitValue())
            };
        } catch (Exception e) {
            return new String[]{ "", e.getMessage(), "-1" };
        } finally {
            if (proc != null && proc.isAlive()) {
                proc.destroyForcibly();
            }
        }
    }

    // Gemini CLI path and model
    private static final String GEMINI_CLI = System.getProperty("user.home") + "/.npm-global/bin/gemini";
    private static final String GEMINI_MODEL = "gemini-2.5-flash-lite";

    public static String execGemini(String prompt) {
        // Try Gemini CLI first
        String geminiResult = execGeminiCli(prompt);
        if (geminiResult != null) return geminiResult;

        // Fallback to OpenRouter
        String apiKey = readFallbackKey();
        if (apiKey == null) {
            log("WARN", "No API key available for LLM query");
            return null;
        }
        return rateLimitAndCallOpenRouter(prompt, apiKey);
    }

    private static String execGeminiCli(String prompt) {
        try {
            // Read Gemini API key
            String geminiKey = readGeminiApiKey();
            if (geminiKey == null) {
                log("WARN", "No Gemini API key found");
                return null;
            }

            // Truncate very long prompts for Gemini CLI
            String truncated = prompt.length() > 8000 ? prompt.substring(0, 8000) + "\n...(truncated)" : prompt;

            ProcessBuilder pb = new ProcessBuilder(
                GEMINI_CLI, "-m", GEMINI_MODEL, "-p", truncated, "--yolo", "--skip-trust");
            pb.redirectErrorStream(true);
            pb.environment().put("GEMINI_API_KEY", geminiKey);
            pb.environment().put("GEMINI_MODEL", GEMINI_MODEL);
            Process proc = pb.start();

            StringBuilder sb = new StringBuilder();
            try (BufferedReader br = new BufferedReader(new InputStreamReader(proc.getInputStream()))) {
                String line;
                while ((line = br.readLine()) != null) sb.append(line).append("\n");
            }
            boolean finished = proc.waitFor(60, TimeUnit.SECONDS);

            if (!finished) {
                proc.destroyForcibly();
                log("WARN", "Gemini CLI timed out after 60s");
                return null;
            }

            String output = sb.toString().strip();
            if (output.isEmpty() || proc.exitValue() != 0) {
                // Detect 503 high demand - fall back immediately
                if (output.contains("503") || output.contains("UNAVAILABLE") || output.contains("high demand")) {
                    log("WARN", "Gemini CLI: 503 high demand, will fallback to OpenRouter");
                    return null;
                }
                log("WARN", "Gemini CLI returned empty or error (exit=" + proc.exitValue() + ")");
                return null;
            }
            // Filter out Gemini CLI status/error messages
            String[] filterLines = {
                "YOLO mode is enabled",
                "Ripgrep is not available",
                "Approval mode overridden",
                "Attempt",
                "failed with status",
                "Retrying with backoff",
                "_ApiError",
                "throwErrorIfNotOK",
                "processTicksAndRejections",
                "generateContentStream",
                "retryWithBackoff",
                "makeApiCallAndProcessStream",
                "streamWithRetries",
                "at async",
                "at Object."
            };
            String[] lines = output.split("\n");
            StringBuilder filtered = new StringBuilder();
            for (String line : lines) {
                boolean skip = false;
                for (String filter : filterLines) {
                    if (line.contains(filter)) { skip = true; break; }
                }
                if (!skip && !line.trim().isEmpty()) filtered.append(line).append("\n");
            }
            return filtered.toString().strip();
        } catch (Exception e) {
            log("WARN", "Gemini CLI not available: " + e.getMessage());
            return null;
        }
    }

    private static final int MAX_RETRY_DEPTH = 1;

    public static String rateLimitAndCallOpenRouter(String prompt, String apiKey) {
        return rateLimitAndCallOpenRouter(prompt, apiKey, 0);
    }

    private static String rateLimitAndCallOpenRouter(String prompt, String apiKey, int depth) {
        synchronized (PACE_EXECUTOR) {
            long now = System.currentTimeMillis();
            long wait = OPENROUTER_PACE_MS - (now - lastOpenRouterCall);
            if (wait > 0) {
                try { Thread.sleep(wait); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
            }
            lastOpenRouterCall = System.currentTimeMillis();
        }

        try {
            // Build JSON payload safely via TrinetraJson, write to temp file to avoid shell injection
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("model", "nvidia/nemotron-3-ultra-550b-a55b:free");
            List<Map<String, String>> messages = new ArrayList<>();
            Map<String, String> msg = new LinkedHashMap<>();
            msg.put("role", "user");
            msg.put("content", prompt);
            messages.add(msg);
            payload.put("messages", messages);
            payload.put("max_tokens", 500);

            Path tmpFile = Path.of(System.getProperty("java.io.tmpdir"), "trinetra_or_payload_" + ProcessHandle.current().pid() + ".json");
            Files.writeString(tmpFile, TrinetraJson.toJson(payload));

            // Direct ProcessBuilder to avoid bash -c overhead
            ProcessBuilder pb = new ProcessBuilder(
                "curl", "-s", "-w", "\n%{http_code}",
                "-X", "POST", "https://openrouter.ai/api/v1/chat/completions",
                "-H", "Content-Type: application/json",
                "-H", "Authorization: Bearer " + apiKey,
                "-d", "@" + tmpFile);
            pb.redirectErrorStream(true);
            Process proc = pb.start();
            StringBuilder sb = new StringBuilder();
            try (BufferedReader br = new BufferedReader(new InputStreamReader(proc.getInputStream()))) {
                String line;
                while ((line = br.readLine()) != null) sb.append(line).append("\n");
            }
            boolean finished = proc.waitFor(60, TimeUnit.SECONDS);
            String rawOutput = finished ? sb.toString().strip() : "";
            try { Files.deleteIfExists(tmpFile); } catch (IOException ignored) {}

            if (!finished) {
                proc.destroyForcibly();
                log("WARN", "OpenRouter curl timed out after 60s");
                return "AI unavailable. The API request timed out.";
            }

            String body = rawOutput;
            int httpCode = -1;
            try {
                String[] parts = rawOutput.split("\n");
                httpCode = Integer.parseInt(parts[parts.length - 1].trim());
                body = String.join("\n", Arrays.copyOf(parts, parts.length - 1));
            } catch (Exception e) {
                String bodyPreview = body != null && body.length() > 200 ? body.substring(0, 200) : body;
                log("WARN", "Failed to parse HTTP code from curl output. body=" + bodyPreview);
            }

            if ((httpCode == 401 || httpCode == 402) && depth < MAX_RETRY_DEPTH) {
                log("WARN", "OpenRouter rate limited (" + httpCode + "), retrying with fallback key...");
                String fallbackKey = readFallbackKey();
                if (fallbackKey != null && !fallbackKey.equals(apiKey)) {
                    return rateLimitAndCallOpenRouter(prompt, fallbackKey, depth + 1);
                }
            }

            if (httpCode == 200) {
                log("INFO", "OpenRouter HTTP 200, parsing response...");
                Object parsed = TrinetraJson.parse(body);
                if (parsed instanceof Map) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> resp = (Map<String, Object>) parsed;
                    List<Map<String, Object>> choices = TrinetraJson.getList(resp, "choices");
                    if (!choices.isEmpty()) {
                        Object message = choices.get(0).get("message");
                        if (message instanceof Map) {
                            return TrinetraJson.getString(message, "content", null);
                        }
                    }
                }
            } else {
                log("WARN", "OpenRouter returned HTTP " + httpCode);
            }
        } catch (Exception e) {
            log("ERROR", "OpenRouter call failed: " + e.getMessage());
        }
        return null;
    }

    private static String readFallbackKey() {
        // Check hexsrtike API key file
        Path hexKeyFile = HEXSTRIKE_DIR.resolve("openrouter_api_key");
        if (Files.exists(hexKeyFile)) {
            try {
                String key = Files.readString(hexKeyFile).strip();
                if (!key.isEmpty()) return key;
            } catch (IOException ignored) {}
        }
        // Check fallback key
        Path keyFile = HEXSTRIKE_DIR.resolve("fallback_key");
        if (Files.exists(keyFile)) {
            try { return Files.readString(keyFile).strip(); } catch (IOException ignored) {}
        }
        // Check .env
        Path envFile = HEXSTRIKE_DIR.resolve(".env");
        if (Files.exists(envFile)) {
            try {
                for (String line : Files.readAllLines(envFile)) {
                    if (line.startsWith("OPENROUTER_API_KEY=")) {
                        return line.substring("OPENROUTER_API_KEY=".length()).strip().replace("\"", "");
                    }
                }
            } catch (IOException ignored) {}
        }
        return null;
    }

    private static String readGeminiApiKey() {
        // Check environment variable first
        String envKey = System.getenv("GEMINI_API_KEY");
        if (envKey != null && !envKey.strip().isEmpty()) return envKey.strip();

        // Check ~/.gemini/settings.json
        Path settingsFile = Path.of(System.getProperty("user.home"), ".gemini", "settings.json");
        if (Files.exists(settingsFile)) {
            try {
                String content = Files.readString(settingsFile);
                // Simple parse: look for "apiKey": "..."
                int idx = content.indexOf("\"apiKey\"");
                if (idx >= 0) {
                    int colonIdx = content.indexOf(':', idx);
                    int quoteStart = content.indexOf('"', colonIdx + 1);
                    int quoteEnd = content.indexOf('"', quoteStart + 1);
                    if (quoteStart >= 0 && quoteEnd >= 0) {
                        return content.substring(quoteStart + 1, quoteEnd).strip();
                    }
                }
            } catch (IOException ignored) {}
        }

        // Check ~/.hexsrtike/gemini_api_key
        Path hexKeyFile = HEXSTRIKE_DIR.resolve("gemini_api_key");
        if (Files.exists(hexKeyFile)) {
            try { return Files.readString(hexKeyFile).strip(); } catch (IOException ignored) {}
        }

        return null;
    }

    public static void log(String level, String msg) {
        String ts = nowIso();
        System.err.println("[" + ts + "] [" + level + "] " + msg);
    }

    public static void logInfo(String msg) { log("INFO", msg); }
    public static void logError(String msg) { log("ERROR", msg); }
    public static void logWarn(String msg) { log("WARN", msg); }

    /** Append to session-specific log file at sessions/<name>/run.log */
    public static void sessionLog(String sessionName, String vCode, String msg) {
        try {
            Path logDir = SESSIONS_DIR.resolve(sanitizeName(sessionName));
            Files.createDirectories(logDir);
            Path logFile = logDir.resolve("run.log");
            String line = "[" + nowIso() + "] [" + vCode + "] " + msg + "\n";
            Files.writeString(logFile, line, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException ignored) {}
    }

    public static long estimateTokens(String text) {
        if (text == null) return 0;
        return Math.max(1, text.length() / 4);
    }

    public static String extractSummaryFromAiResponse(String response) {
        if (response == null) return null;
        String cleaned = response.trim();
        // Strip markdown code fences if present
        if (cleaned.startsWith("```")) {
            int firstNewline = cleaned.indexOf('\n');
            if (firstNewline > 0) cleaned = cleaned.substring(firstNewline + 1);
            if (cleaned.endsWith("```")) cleaned = cleaned.substring(0, cleaned.length() - 3);
        }
        return cleaned.strip();
    }

    // ── JSON helper methods ──

    public static String getString(Object val, String key, String def) {
        if (val instanceof Map) {
            Object v = ((Map<?, ?>) val).get(key);
            return v != null ? v.toString() : def;
        }
        return def;
    }

    public static int getInt(Object val, String key, int def) {
        if (val instanceof Map) {
            Object v = ((Map<?, ?>) val).get(key);
            if (v instanceof Number) return ((Number) v).intValue();
            if (v instanceof String) {
                try { return Integer.parseInt((String) v); } catch (Exception e) { return def; }
            }
        }
        return def;
    }

    @SuppressWarnings("unchecked")
    public static List<Map<String, Object>> getList(Object val, String key) {
        if (val instanceof Map) {
            Object v = ((Map<?, ?>) val).get(key);
            if (v instanceof List) {
                List<Object> raw = (List<Object>) v;
                List<Map<String, Object>> result = new ArrayList<>();
                for (Object item : raw) {
                    if (item instanceof Map) result.add((Map<String, Object>) item);
                }
                return result;
            }
        }
        return new ArrayList<>();
    }

    @SuppressWarnings("unchecked")
    public static List<String> getStringList(Object val, String key) {
        if (val instanceof Map) {
            Object v = ((Map<?, ?>) val).get(key);
            if (v instanceof List) {
                List<String> result = new ArrayList<>();
                for (Object item : (List<Object>) v) {
                    result.add(item != null ? item.toString() : "");
                }
                return result;
            }
        }
        return new ArrayList<>();
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> getMap(Object val, String key) {
        if (val instanceof Map) {
            Object v = ((Map<?, ?>) val).get(key);
            if (v instanceof Map) return (Map<String, Object>) v;
        }
        return new LinkedHashMap<>();
    }

    public static Map<String, Object> newMap() { return new LinkedHashMap<>(); }

    @SafeVarargs
    public static Map<String, Object> mapOf(String... keysAndValues) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i + 1 < keysAndValues.length; i += 2) {
            m.put(keysAndValues[i], keysAndValues[i + 1]);
        }
        return m;
    }

    public static List<Object> newList() { return new ArrayList<>(); }
}
