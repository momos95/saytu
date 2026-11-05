package com.saytu.app.scan;

import com.saytu.git.json.JsonNode;

import java.math.BigDecimal;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

/** Minimal JSON for the JSONB columns written with JDBC (maps, lists, strings, numbers, booleans). */
final class Json {

    private Json() {
    }

    static String write(Object value) {
        StringBuilder sb = new StringBuilder();
        write(value, sb);
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private static void write(Object value, StringBuilder sb) {
        if (value == null) {
            sb.append("null");
        } else if (value instanceof Map<?, ?> map) {
            sb.append('{');
            boolean first = true;
            for (var e : ((Map<Object, Object>) map).entrySet()) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                sb.append(ScanPlanner.quote(String.valueOf(e.getKey()))).append(':');
                write(e.getValue(), sb);
            }
            sb.append('}');
        } else if (value instanceof Collection<?> list) {
            sb.append('[');
            boolean first = true;
            for (Object o : list) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                write(o, sb);
            }
            sb.append(']');
        } else if (value instanceof Double d) {
            sb.append(d.isNaN() || d.isInfinite() ? "null" : BigDecimal.valueOf(d).stripTrailingZeros().toPlainString());
        } else if (value instanceof Float f) {
            write(f.doubleValue(), sb);
        } else if (value instanceof BigDecimal bd) {
            sb.append(bd.toPlainString());
        } else if (value instanceof Number || value instanceof Boolean) {
            sb.append(value);
        } else {
            sb.append(ScanPlanner.quote(value.toString()));
        }
    }

    /** Object as a map; empty map for null, blank or non-object JSON. */
    @SuppressWarnings("unchecked")
    static Map<String, Object> read(String json) {
        if (json == null || json.isBlank()) {
            return Map.of();
        }
        Object o = JsonNode.parse(json).toJava();
        return o instanceof Map<?, ?> m ? (Map<String, Object>) m : new LinkedHashMap<>();
    }
}
