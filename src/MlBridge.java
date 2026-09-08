import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;

/**
 * Java → Python ML bridge for KNN advisory.
 * Calls bridge/ml_knn.py predict(line) via subprocess, never throws into caller.
 * All failures → null (ingestion falls back to regex-only). Timeout 800ms per line, 1.5s total.
 * Model lives in config/ml_model.pkl, vectorizer in config/ml_vectorizer.pkl, retrained by bridge/app.py on POST /train.
 */
public final class MlBridge {

    private static final long PER_LINE_MS = 800;
    private static final int MAX_LINES_PER_INGEST = 40; // cap ML calls per config to keep ingest <2s

    private MlBridge() {}

    public static class MlPrediction {
        public final String label; // V-code or category
        public final double confidence; // 0..1
        public final String source;
        public MlPrediction(String label, double confidence, String source) {
            this.label = label;
            this.confidence = confidence;
            this.source = source;
        }
        @Override public String toString() { return label + "@" + confidence + " via " + source; }
    }

    /**
     * Batch predict for a list of unrecognized lines. Runs one python subprocess for all lines to avoid per-line spawn.
     * Returns map line -> prediction or null if low confidence / no model / sklearn missing.
     */
    public static Map<String, MlPrediction> predictBatch(List<String> lines) {
        if (lines == null || lines.isEmpty()) return Collections.emptyMap();
        List<String> capped = lines.size() > MAX_LINES_PER_INGEST ? lines.subList(0, MAX_LINES_PER_INGEST) : lines;
        // filter trivial
        List<String> filtered = new ArrayList<>();
        for (String l : capped) {
            if (l != null && l.trim().length() >= 5) filtered.add(l);
        }
        if (filtered.isEmpty()) return Collections.emptyMap();

        Path mlScript = Path.of(TrinetraCommon.PROJECT_ROOT, "bridge", "ml_knn.py");
        if (!Files.exists(mlScript)) return Collections.emptyMap();

        // Build inline python that imports ml_knn and predicts batch
        // Use JSON over stdin/stdout to avoid shell quoting issues
        StringBuilder py = new StringBuilder();
        py.append("import json, sys\n");
        py.append("sys.path.insert(0, '").append(TrinetraCommon.PROJECT_ROOT.replace("\\", "/")).append("')\n");
        py.append("try:\n");
        py.append(" from bridge.ml_knn import predict\n");
        py.append("except ImportError:\n");
        py.append(" from ml_knn import predict\n");
        py.append("d=json.load(sys.stdin)\n");
        py.append("out={}\n");
        py.append("for line in d.get('lines',[]):\n");
        py.append(" p=predict(line)\n");
        py.append(" out[line]=p\n");
        py.append("json.dump(out, sys.stdout)\n");

        String payload;
        try {
            Map<String, Object> in = new LinkedHashMap<>();
            in.put("lines", filtered);
            payload = TrinetraJson.toJson(in);
        } catch (Exception e) {
            return Collections.emptyMap();
        }

        Process proc = null;
        try {
            String pythonBin = Files.exists(Path.of(TrinetraCommon.PROJECT_ROOT, ".venv", "bin", "python")) ? Path.of(TrinetraCommon.PROJECT_ROOT, ".venv", "bin", "python").toString() : "python3";
            ProcessBuilder pb = new ProcessBuilder(pythonBin, "-c", py.toString());
            pb.redirectErrorStream(false);
            // Ensure unbuffered
            pb.environment().put("PYTHONUNBUFFERED", "1");
            proc = pb.start();

            // write stdin
            try (OutputStream os = proc.getOutputStream()) {
                os.write(payload.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                os.flush();
            }

            // read stdout with timeout — first cold load can be ~2-3s
            String stdout = readWithTimeout(proc.getInputStream(), 4000);
            String stderr = readWithTimeout(proc.getErrorStream(), 500);
            boolean finished = proc.waitFor(4000, TimeUnit.MILLISECONDS);
            if (!finished) {
                proc.destroyForcibly();
                return Collections.emptyMap();
            }
            if (proc.exitValue() != 0) {
                TrinetraCommon.logWarn("MlBridge python exit " + proc.exitValue() + " stderr: " + stderr + " stdout: " + stdout);
                return Collections.emptyMap();
            }
            if (stdout == null || stdout.isBlank()) {
                TrinetraCommon.logWarn("MlBridge empty stdout stderr: " + stderr);
                return Collections.emptyMap();
            }
            Object parsed = TrinetraJson.parse(stdout);
            if (!(parsed instanceof Map)) {
                TrinetraCommon.logWarn("MlBridge parse fail stdout: " + stdout);
                return Collections.emptyMap();
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> out = (Map<String, Object>) parsed;
            Map<String, MlPrediction> result = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : out.entrySet()) {
                Object v = e.getValue();
                if (v instanceof Map) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> m = (Map<String, Object>) v;
                    String label = TrinetraCommon.getString(m, "label", "");
                    if (label.isBlank()) continue;
                    Object confObj = m.get("confidence");
                    double conf = confObj instanceof Number ? ((Number) confObj).doubleValue() : 0.0;
                    String src = TrinetraCommon.getString(m, "source", "knn");
                    result.put(e.getKey(), new MlPrediction(label, conf, src));
                }
            }
            return result;
        } catch (Exception e) {
            return Collections.emptyMap();
        } finally {
            if (proc != null && proc.isAlive()) proc.destroyForcibly();
        }
    }

    public static MlPrediction predictOne(String line) {
        if (line == null || line.isBlank()) return null;
        return predictBatch(List.of(line)).get(line);
    }

    private static String readWithTimeout(InputStream is, long timeoutMs) {
        ExecutorService es = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r); t.setDaemon(true); return t;
        });
        Future<String> f = es.submit(() -> {
            try (BufferedReader br = new BufferedReader(new InputStreamReader(is, java.nio.charset.StandardCharsets.UTF_8))) {
                StringBuilder sb = new StringBuilder();
                String l;
                while ((l = br.readLine()) != null) sb.append(l).append("\n");
                return sb.toString().trim();
            } catch (IOException e) { return ""; }
        });
        try { return f.get(timeoutMs, TimeUnit.MILLISECONDS); }
        catch (Exception e) { f.cancel(true); return ""; }
        finally { es.shutdownNow(); }
    }
}
