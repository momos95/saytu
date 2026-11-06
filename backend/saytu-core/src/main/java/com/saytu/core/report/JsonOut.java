package com.saytu.core.report;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Collection;
import java.util.Map;

/** Minimal streaming JSON writer (no dependency): objects, arrays, escaped strings, numbers, booleans. */
final class JsonOut {

    private final StringBuilder out = new StringBuilder(4096);
    /** true when the next value in the current container needs a comma before it */
    private boolean comma;

    JsonOut beginObject() {
        separator();
        out.append('{');
        comma = false;
        return this;
    }

    JsonOut endObject() {
        out.append('}');
        comma = true;
        return this;
    }

    JsonOut beginArray() {
        separator();
        out.append('[');
        comma = false;
        return this;
    }

    JsonOut endArray() {
        out.append(']');
        comma = true;
        return this;
    }

    JsonOut name(String name) {
        separator();
        string(name);
        out.append(':');
        comma = false;
        return this;
    }

    JsonOut value(Object value) {
        separator();
        switch (value) {
            case null -> out.append("null");
            case String s -> string(s);
            case Boolean b -> out.append(b);
            case BigDecimal d -> out.append(d.stripTrailingZeros().toPlainString());
            case Double d -> out.append(d.isNaN() || d.isInfinite() ? "null" : number(d));
            case Number n -> out.append(n);
            case Instant i -> string(i.toString());
            case Collection<?> c -> {
                out.append('[');
                comma = false;
                for (Object o : c) {
                    value(o);
                }
                out.append(']');
            }
            case Map<?, ?> m -> {
                out.append('{');
                comma = false;
                for (Map.Entry<?, ?> e : m.entrySet()) {
                    name(String.valueOf(e.getKey()));
                    value(e.getValue());
                }
                out.append('}');
            }
            default -> string(value.toString());
        }
        comma = true;
        return this;
    }

    /** name + value; nulls are written as null (stable shape for consumers). */
    JsonOut field(String name, Object value) {
        return name(name).value(value);
    }

    /** name + value, skipped when the value is null or an empty collection (SARIF style). */
    JsonOut optional(String name, Object value) {
        if (value == null || value instanceof Collection<?> c && c.isEmpty() || value instanceof Map<?, ?> m && m.isEmpty()) {
            return this;
        }
        return field(name, value);
    }

    private static String number(double d) {
        return d == Math.rint(d) && Math.abs(d) < 1e15 ? Long.toString((long) d) : BigDecimal.valueOf(d).toPlainString();
    }

    private void separator() {
        if (comma) {
            out.append(',');
        }
    }

    private void string(String s) {
        out.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    // also escape < > & and line separators so the JSON can be embedded safely
                    if (c < 0x20 || c == '<' || c == '>' || c == '&' || c == ' ' || c == ' ') {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }

    @Override
    public String toString() {
        return out.toString();
    }
}
