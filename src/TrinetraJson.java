import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;

/**
 * Minimal JSON utility for Trinetra beta.
 * Handles construction and parsing of the specific JSON structures
 * used in session files, brain state, and global state.
 */
public class TrinetraJson {

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

    public static Map<String, Object> getMap(Object val, String key) {
        if (val instanceof Map) {
            Object v = ((Map<?, ?>) val).get(key);
            if (v instanceof Map) return (Map<String, Object>) v;
        }
        return new HashMap<>();
    }

    public static Object parse(String json) {
        return new JsonParser(json.trim()).parseValue();
    }

    public static String toJson(Object obj) {
        StringBuilder sb = new StringBuilder();
        writeValue(sb, obj);
        return sb.toString();
    }

    public static String prettyJson(Object obj) {
        StringBuilder sb = new StringBuilder();
        writePretty(sb, obj, 0);
        return sb.toString();
    }

    private static void writeValue(StringBuilder sb, Object val) {
        if (val == null) { sb.append("null"); }
        else if (val instanceof String) { sb.append('"').append(escape((String) val)).append('"'); }
        else if (val instanceof Number) { sb.append(val); }
        else if (val instanceof Boolean) { sb.append(val); }
        else if (val instanceof Map) {
            sb.append('{');
            boolean first = true;
            @SuppressWarnings("unchecked")
            Map<String, Object> map = (Map<String, Object>) val;
            for (Map.Entry<String, Object> e : map.entrySet()) {
                if (!first) sb.append(',');
                sb.append('"').append(escape(e.getKey())).append('"').append(':');
                writeValue(sb, e.getValue());
                first = false;
            }
            sb.append('}');
        } else if (val instanceof List) {
            sb.append('[');
            boolean first = true;
            for (Object item : (List<?>) val) {
                if (!first) sb.append(',');
                writeValue(sb, item);
                first = false;
            }
            sb.append(']');
        } else {
            sb.append('"').append(escape(val.toString())).append('"');
        }
    }

    private static void writePretty(StringBuilder sb, Object val, int indent) {
        String pad = "  ".repeat(indent);
        if (val == null) { sb.append("null"); }
        else if (val instanceof String) { sb.append('"').append(escape((String) val)).append('"'); }
        else if (val instanceof Number) { sb.append(val); }
        else if (val instanceof Boolean) { sb.append(val); }
        else if (val instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> map = (Map<String, Object>) val;
            if (map.isEmpty()) { sb.append("{}"); return; }
            sb.append("{\n");
            boolean first = true;
            for (Map.Entry<String, Object> e : map.entrySet()) {
                if (!first) sb.append(",\n");
                sb.append("  ".repeat(indent + 1)).append('"').append(escape(e.getKey())).append("\": ");
                writePretty(sb, e.getValue(), indent + 1);
                first = false;
            }
            sb.append("\n").append(pad).append("}");
        } else if (val instanceof List) {
            List<?> list = (List<?>) val;
            if (list.isEmpty()) { sb.append("[]"); return; }
            sb.append("[\n");
            boolean first = true;
            for (Object item : list) {
                if (!first) sb.append(",\n");
                sb.append("  ".repeat(indent + 1));
                writePretty(sb, item, indent + 1);
                first = false;
            }
            sb.append("\n").append(pad).append("]");
        } else {
            sb.append('"').append(escape(val.toString())).append('"');
        }
    }

    private static String escape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }

    public static Map<String, Object> newMap() { return new LinkedHashMap<>(); }

    public static Map<String, Object> mapOf(String... keysAndValues) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i + 1 < keysAndValues.length; i += 2) {
            m.put(keysAndValues[i], keysAndValues[i + 1]);
        }
        return m;
    }

    public static List<Object> newList() { return new ArrayList<>(); }

    static class JsonParser {
        private final String json;
        private int pos;

        JsonParser(String json) { this.json = json; }

        Object parseValue() {
            skipWhitespace();
            if (pos >= json.length()) return null;
            char c = json.charAt(pos);
            if (c == '"') return parseString();
            if (c == '{') return parseObject();
            if (c == '[') return parseArray();
            if (c == 't' || c == 'f') return parseBoolean();
            if (c == 'n') { pos += 4; return null; }
            return parseNumber();
        }

        private String parseString() {
            pos++; // skip opening quote
            StringBuilder sb = new StringBuilder();
            while (pos < json.length()) {
                char c = json.charAt(pos++);
                if (c == '"') return sb.toString();
                if (c == '\\') {
                    char n = json.charAt(pos++);
                    switch (n) {
                        case '"': sb.append('"'); break;
                        case '\\': sb.append('\\'); break;
                        case '/': sb.append('/'); break;
                        case 'n': sb.append('\n'); break;
                        case 'r': sb.append('\r'); break;
                        case 't': sb.append('\t'); break;
                        case 'u':
                            String hex = json.substring(pos, pos + 4);
                            sb.append((char) Integer.parseInt(hex, 16));
                            pos += 4;
                            break;
                        default: sb.append(n);
                    }
                } else {
                    sb.append(c);
                }
            }
            return sb.toString();
        }

        private Map<String, Object> parseObject() {
            pos++; // skip {
            Map<String, Object> map = new LinkedHashMap<>();
            skipWhitespace();
            if (pos < json.length() && json.charAt(pos) == '}') { pos++; return map; }
            while (pos < json.length()) {
                skipWhitespace();
                String key = parseString();
                skipWhitespace();
                pos++; // skip :
                Object val = parseValue();
                map.put(key, val);
                skipWhitespace();
                if (pos < json.length() && json.charAt(pos) == ',') { pos++; continue; }
                break;
            }
            skipWhitespace();
            if (pos < json.length() && json.charAt(pos) == '}') pos++;
            return map;
        }

        private List<Object> parseArray() {
            pos++; // skip [
            List<Object> list = new ArrayList<>();
            skipWhitespace();
            if (pos < json.length() && json.charAt(pos) == ']') { pos++; return list; }
            while (pos < json.length()) {
                list.add(parseValue());
                skipWhitespace();
                if (pos < json.length() && json.charAt(pos) == ',') { pos++; continue; }
                break;
            }
            skipWhitespace();
            if (pos < json.length() && json.charAt(pos) == ']') pos++;
            return list;
        }

        private Object parseNumber() {
            int start = pos;
            if (pos < json.length() && json.charAt(pos) == '-') pos++;
            while (pos < json.length() && Character.isDigit(json.charAt(pos))) pos++;
            boolean isFloat = false;
            if (pos < json.length() && json.charAt(pos) == '.') {
                isFloat = true;
                pos++;
                while (pos < json.length() && Character.isDigit(json.charAt(pos))) pos++;
            }
            if (pos < json.length() && (json.charAt(pos) == 'e' || json.charAt(pos) == 'E')) {
                isFloat = true;
                pos++;
                if (pos < json.length() && (json.charAt(pos) == '+' || json.charAt(pos) == '-')) pos++;
                while (pos < json.length() && Character.isDigit(json.charAt(pos))) pos++;
            }
            String numStr = json.substring(start, pos);
            if (isFloat) return Double.parseDouble(numStr);
            long val = Long.parseLong(numStr);
            if (val >= Integer.MIN_VALUE && val <= Integer.MAX_VALUE) return (int) val;
            return val;
        }

        private Boolean parseBoolean() {
            if (json.startsWith("true", pos)) { pos += 4; return true; }
            pos += 5; return false;
        }

        private void skipWhitespace() {
            while (pos < json.length() && Character.isWhitespace(json.charAt(pos))) pos++;
        }
    }
}
