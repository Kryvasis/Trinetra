import java.util.*;
import java.util.regex.*;

/**
 * NLP Pattern Recognition bridge — uses Gemini LLM to interpret unknown config syntax
 * via natural language understanding, not just regex/KNN. Complements the lightweight KNN
 * advisory with true semantic reasoning for unseen vendor syntax.
 */
public class NlpBridge {

    public static class NlpPrediction {
        public final String category;
        public final String control;
        public final String remediation;
        public final double confidence;
        public final String reasoning;
        public NlpPrediction(String category, String control, String remediation, double confidence, String reasoning) {
            this.category = category;
            this.control = control;
            this.remediation = remediation;
            this.confidence = confidence;
            this.reasoning = reasoning;
        }
    }

    /**
     * Use Gemini to interpret an unknown config line and suggest security category + control mapping.
     * Returns null if LLM unavailable or low confidence.
     */
    public static NlpPrediction suggest(String configLine, String vendorHint) {
        if (configLine == null || configLine.isBlank()) return null;
        String prompt = buildPrompt(configLine, vendorHint);
        String response = TrinetraCommon.execGemini(prompt);
        if (response == null || response.isBlank()) return null;
        return parseResponse(response, configLine);
    }

    private static String buildPrompt(String line, String vendor) {
        return String.join("\n",
            "You are a network security compliance expert. Analyze this network device configuration line:",
            "Vendor hint: " + (vendor != null ? vendor : "unknown"),
            "Config line: \"" + line + "\"",
            "",
            "Task: Map this line to a security category and compliance control.",
            "Categories: one of [Access Control, Cryptography, Logging, Network Segmentation, Authentication, Management Plane, SNMP, System Hardening]",
            "Controls: map to CIS/NIST/STIG/ISO terms like CIS-v8-4.6, NIST AC-4, CISC-ND-000015, ISO27001-A.9.4.1 etc.",
            "Respond ONLY in JSON: {\"category\":\"...\",\"control\":\"...\",\"remediation\":\"step-by-step fix\",\"confidence\":0.0-1.0,\"reasoning\":\"...\"}",
            "If unsure, set confidence <0.5. Never invent a control not in the list."
        );
    }

    private static NlpPrediction parseResponse(String response, String originalLine) {
        try {
            // Extract JSON block
            int start = response.indexOf("{");
            int end = response.lastIndexOf("}");
            if (start < 0 || end < 0) return null;
            String json = response.substring(start, end + 1);
            Object parsed = TrinetraJson.parse(json);
            if (!(parsed instanceof Map)) return null;
            @SuppressWarnings("unchecked")
            Map<String, Object> m = (Map<String, Object>) parsed;
            String category = TrinetraCommon.getString(m, "category", "");
            String control = TrinetraCommon.getString(m, "control", "");
            String remediation = TrinetraCommon.getString(m, "remediation", "");
            Object confObj = m.get("confidence");
            double conf = 0.0;
            if (confObj instanceof Number) conf = ((Number) confObj).doubleValue();
            else if (confObj instanceof String) try { conf = Double.parseDouble((String) confObj); } catch (Exception ignored) {}
            String reasoning = TrinetraCommon.getString(m, "reasoning", "");
            if (category.isBlank() || conf < 0.5) return null;
            return new NlpPrediction(category, control, remediation, Math.min(1.0, Math.max(0.0, conf)), reasoning);
        } catch (Exception e) {
            TrinetraCommon.logWarn("NLP parse failed for line: " + originalLine + " -> " + e.getMessage());
            return null;
        }
    }

    /**
     * Batch suggest for multiple lines — sequential with pacing to avoid rate limits.
     */
    public static Map<String, NlpPrediction> suggestBatch(List<String> lines, String vendorHint) {
        Map<String, NlpPrediction> out = new LinkedHashMap<>();
        if (lines == null || lines.isEmpty()) return out;
        for (String line : lines) {
            try {
                NlpPrediction p = suggest(line, vendorHint);
                if (p != null) out.put(line, p);
                // Small pacing to respect OpenRouter 3s limit via TrinetraCommon
                Thread.sleep(100);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception ignored) {}
            if (out.size() >= 5) break; // Limit to 5 per batch for latency
        }
        return out;
    }
}
