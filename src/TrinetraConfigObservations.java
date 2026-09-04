import java.util.*;
import java.util.regex.*;

/** Bounded IOS-style text observations, NOT runtime tests or benchmark verdicts. */
public final class TrinetraConfigObservations {
    public static Map<String, Object> review(String vendor, String content) {
        Map<String, Object> review = new LinkedHashMap<>();
        boolean supported = "Cisco".equals(vendor) && !content.toLowerCase(Locale.ROOT).contains("nx-os");
        review.put("parser", supported ? "ios-text-observations-v1" : "unsupported");
        review.put("scope", "Explicit directives in supplied text only. Absence is not a pass; comments and banners are excluded. Does not establish effective configuration, reachability, authentication, or compliance.");
        List<Map<String, Object>> observations = new ArrayList<>();
        review.put("observations", observations);
        if (!supported) return review;
        String[][] rules = {
            {"CFG-SSH1", "SSH version 1 directive", "ip\\s+ssh\\s+version\\s+1", "Verify supported SSHv2 configuration and effective service state for this OS version."},
            {"CFG-HTTP", "Unencrypted HTTP server directive", "ip\\s+http\\s+server", "Review whether HTTP management is needed and verify encrypted management and access restrictions."},
            {"CFG-TELNET", "Telnet-capable inbound transport directive", "transport\\s+input\\s+(?:.*\\btelnet\\b.*|all)", "Review the enclosing line context and migrate management access to an approved encrypted protocol."},
            {"CFG-SNMP", "Default SNMP community directive", "snmp-server\\s+community\\s+(?:public|private)(?:\\s+.*)?", "Review SNMP necessity, community exposure and supported authenticated/encrypted alternatives."},
            {"CFG-PASSWORD", "Type 0 or type 7 password directive", "(?:username\\s+\\S+\\s+(?:privilege\\s+\\d+\\s+)?password|enable\\s+password|password)\\s+[07]\\s+.+", "Review supported secret storage for this platform; rotate exposed credentials using a reviewed change plan."}
        };
        List<String> lines = Arrays.asList(content.split("\\r?\\n", -1));
        Set<Integer> ignored = new HashSet<>();
        String delimiter = null;
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i).trim();
            if (delimiter != null) {
                ignored.add(i);
                if (line.contains(delimiter)) delimiter = null;
                continue;
            }
            if (line.startsWith("!") || line.startsWith("#")) ignored.add(i);
            Matcher banner = Pattern.compile("(?i)^banner\\s+\\S+\\s+(.+)$").matcher(line);
            if (banner.find()) {
                ignored.add(i);
                String text = banner.group(1);
                String token = text.startsWith("^") && text.length() > 1 ? text.substring(0, 2) : text.substring(0, 1);
                if (!text.substring(token.length()).contains(token)) delimiter = token;
            }
        }
        for (String[] rule : rules) {
            Pattern pattern = Pattern.compile("^(?:" + rule[2] + ")$", Pattern.CASE_INSENSITIVE);
            List<Integer> evidenceLines = new ArrayList<>();
            for (int i = 0; i < lines.size(); i++) {
                if (!ignored.contains(i) && pattern.matcher(lines.get(i).trim()).matches()) evidenceLines.add(i + 1);
            }
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("id", rule[0]); row.put("title", rule[1]);
            row.put("status", evidenceLines.isEmpty() ? "not_observed" : "observed_risk");
            // Store locations, never repeat passwords or community strings in summaries.
            row.put("line_numbers", evidenceLines); row.put("next_step", rule[3]);
            observations.add(row);
        }
        return review;
    }
}
