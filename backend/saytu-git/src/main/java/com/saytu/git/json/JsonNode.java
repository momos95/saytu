package com.saytu.git.json;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Minimal, strict RFC 8259 JSON reader for Git platform API responses.
 * <p>
 * Read-only and navigation-oriented: {@code node.get("owner").get("login").asText()} never throws,
 * missing paths yield {@link #MISSING}. Nesting depth is bounded to resist hostile payloads; the
 * caller bounds the input size. Kept dependency-free on purpose (see ADR-0005).
 */
public final class JsonNode {

    public static final JsonNode MISSING = new JsonNode(Kind.MISSING, null);
    public static final JsonNode NULL = new JsonNode(Kind.NULL, null);

    static final int MAX_DEPTH = 64;

    private enum Kind { MISSING, NULL, OBJECT, ARRAY, STRING, NUMBER, BOOLEAN }

    private final Kind kind;
    private final Object value;

    private JsonNode(Kind kind, Object value) {
        this.kind = kind;
        this.value = value;
    }

    public static JsonNode parse(String json) {
        if (json == null) {
            throw new JsonParseException("null input", 0);
        }
        Parser parser = new Parser(json);
        JsonNode node = parser.readValue(0);
        parser.skipWhitespace();
        if (parser.pos != json.length()) {
            throw new JsonParseException("unexpected trailing content", parser.pos);
        }
        return node;
    }

    // ------------------------------------------------------------------ navigation

    public JsonNode get(String field) {
        if (kind != Kind.OBJECT) {
            return MISSING;
        }
        JsonNode child = asMap().get(field);
        return child == null ? MISSING : child;
    }

    public JsonNode get(int index) {
        if (kind != Kind.ARRAY || index < 0 || index >= asList().size()) {
            return MISSING;
        }
        return asList().get(index);
    }

    public List<JsonNode> elements() {
        return kind == Kind.ARRAY ? asList() : List.of();
    }

    public int size() {
        return switch (kind) {
            case ARRAY -> asList().size();
            case OBJECT -> asMap().size();
            default -> 0;
        };
    }

    public boolean isMissing() {
        return kind == Kind.MISSING;
    }

    public boolean isNull() {
        return kind == Kind.NULL;
    }

    /** Missing or JSON null. */
    public boolean isAbsent() {
        return kind == Kind.MISSING || kind == Kind.NULL;
    }

    public boolean isObject() {
        return kind == Kind.OBJECT;
    }

    public boolean isArray() {
        return kind == Kind.ARRAY;
    }

    public boolean isTextual() {
        return kind == Kind.STRING;
    }

    /** String, number or boolean as text; {@code null} for other kinds. */
    public String asText() {
        return switch (kind) {
            case STRING -> (String) value;
            case NUMBER -> ((BigDecimal) value).toPlainString();
            case BOOLEAN -> value.toString();
            default -> null;
        };
    }

    public Optional<String> text(String field) {
        String t = get(field).asText();
        return t == null || t.isEmpty() ? Optional.empty() : Optional.of(t);
    }

    public long asLong(long defaultValue) {
        if (kind == Kind.NUMBER) {
            try {
                return ((BigDecimal) value).longValueExact();
            } catch (ArithmeticException e) {
                return defaultValue;
            }
        }
        if (kind == Kind.STRING) {
            try {
                return Long.parseLong((String) value);
            } catch (NumberFormatException e) {
                return defaultValue;
            }
        }
        return defaultValue;
    }

    public boolean asBoolean(boolean defaultValue) {
        return kind == Kind.BOOLEAN ? (Boolean) value : defaultValue;
    }

    /** String elements of an array (other kinds skipped). */
    public List<String> textElements() {
        List<String> result = new ArrayList<>();
        for (JsonNode n : elements()) {
            if (n.isTextual()) {
                result.add(n.asText());
            }
        }
        return List.copyOf(result);
    }

    @SuppressWarnings("unchecked")
    private Map<String, JsonNode> asMap() {
        return (Map<String, JsonNode>) value;
    }

    @SuppressWarnings("unchecked")
    private List<JsonNode> asList() {
        return (List<JsonNode>) value;
    }

    @Override
    public String toString() {
        return switch (kind) {
            case MISSING -> "<missing>";
            case NULL -> "null";
            case STRING -> '"' + (String) value + '"';
            default -> String.valueOf(value);
        };
    }

    // ------------------------------------------------------------------ parser

    private static final class Parser {
        private final String s;
        private int pos;

        Parser(String s) {
            this.s = s;
        }

        JsonNode readValue(int depth) {
            if (depth > MAX_DEPTH) {
                throw new JsonParseException("nesting deeper than " + MAX_DEPTH, pos);
            }
            skipWhitespace();
            if (pos >= s.length()) {
                throw new JsonParseException("unexpected end of input", pos);
            }
            char c = s.charAt(pos);
            return switch (c) {
                case '{' -> readObject(depth);
                case '[' -> readArray(depth);
                case '"' -> new JsonNode(Kind.STRING, readString());
                case 't' -> literal("true", new JsonNode(Kind.BOOLEAN, Boolean.TRUE));
                case 'f' -> literal("false", new JsonNode(Kind.BOOLEAN, Boolean.FALSE));
                case 'n' -> literal("null", NULL);
                default -> {
                    if (c == '-' || (c >= '0' && c <= '9')) {
                        yield readNumber();
                    }
                    throw new JsonParseException("unexpected character '" + c + "'", pos);
                }
            };
        }

        private JsonNode readObject(int depth) {
            pos++; // {
            Map<String, JsonNode> map = new LinkedHashMap<>();
            skipWhitespace();
            if (peek() == '}') {
                pos++;
                return new JsonNode(Kind.OBJECT, Collections.unmodifiableMap(map));
            }
            while (true) {
                skipWhitespace();
                if (peek() != '"') {
                    throw new JsonParseException("expected field name", pos);
                }
                String key = readString();
                skipWhitespace();
                expect(':');
                map.put(key, readValue(depth + 1));
                skipWhitespace();
                char c = next();
                if (c == '}') {
                    return new JsonNode(Kind.OBJECT, Collections.unmodifiableMap(map));
                }
                if (c != ',') {
                    throw new JsonParseException("expected ',' or '}'", pos - 1);
                }
            }
        }

        private JsonNode readArray(int depth) {
            pos++; // [
            List<JsonNode> list = new ArrayList<>();
            skipWhitespace();
            if (peek() == ']') {
                pos++;
                return new JsonNode(Kind.ARRAY, Collections.unmodifiableList(list));
            }
            while (true) {
                list.add(readValue(depth + 1));
                skipWhitespace();
                char c = next();
                if (c == ']') {
                    return new JsonNode(Kind.ARRAY, Collections.unmodifiableList(list));
                }
                if (c != ',') {
                    throw new JsonParseException("expected ',' or ']'", pos - 1);
                }
            }
        }

        private String readString() {
            pos++; // opening quote
            StringBuilder sb = new StringBuilder();
            while (true) {
                if (pos >= s.length()) {
                    throw new JsonParseException("unterminated string", pos);
                }
                char c = s.charAt(pos++);
                if (c == '"') {
                    return sb.toString();
                }
                if (c < 0x20) {
                    throw new JsonParseException("control character in string", pos - 1);
                }
                if (c != '\\') {
                    sb.append(c);
                    continue;
                }
                char e = next();
                switch (e) {
                    case '"', '\\', '/' -> sb.append(e);
                    case 'b' -> sb.append('\b');
                    case 'f' -> sb.append('\f');
                    case 'n' -> sb.append('\n');
                    case 'r' -> sb.append('\r');
                    case 't' -> sb.append('\t');
                    case 'u' -> {
                        if (pos + 4 > s.length()) {
                            throw new JsonParseException("truncated unicode escape", pos);
                        }
                        try {
                            sb.append((char) Integer.parseInt(s.substring(pos, pos + 4), 16));
                        } catch (NumberFormatException ex) {
                            throw new JsonParseException("invalid unicode escape", pos);
                        }
                        pos += 4;
                    }
                    default -> throw new JsonParseException("invalid escape '\\" + e + "'", pos - 1);
                }
            }
        }

        private JsonNode readNumber() {
            int start = pos;
            if (peek() == '-') {
                pos++;
            }
            if (peek() == '0') {
                pos++;
            } else if (isDigit(peek())) {
                while (isDigit(peek())) {
                    pos++;
                }
            } else {
                throw new JsonParseException("invalid number", start);
            }
            if (peek() == '.') {
                pos++;
                if (!isDigit(peek())) {
                    throw new JsonParseException("invalid number", start);
                }
                while (isDigit(peek())) {
                    pos++;
                }
            }
            if (peek() == 'e' || peek() == 'E') {
                pos++;
                if (peek() == '+' || peek() == '-') {
                    pos++;
                }
                if (!isDigit(peek())) {
                    throw new JsonParseException("invalid number", start);
                }
                while (isDigit(peek())) {
                    pos++;
                }
            }
            String raw = s.substring(start, pos);
            if (raw.length() > 100) {
                throw new JsonParseException("number too long", start);
            }
            return new JsonNode(Kind.NUMBER, new BigDecimal(raw));
        }

        private JsonNode literal(String word, JsonNode node) {
            if (!s.startsWith(word, pos)) {
                throw new JsonParseException("invalid literal", pos);
            }
            pos += word.length();
            return node;
        }

        void skipWhitespace() {
            while (pos < s.length()) {
                char c = s.charAt(pos);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                    pos++;
                } else {
                    break;
                }
            }
        }

        private char peek() {
            return pos < s.length() ? s.charAt(pos) : '\0';
        }

        private char next() {
            if (pos >= s.length()) {
                throw new JsonParseException("unexpected end of input", pos);
            }
            return s.charAt(pos++);
        }

        private void expect(char c) {
            if (next() != c) {
                throw new JsonParseException("expected '" + c + "'", pos - 1);
            }
        }

        private static boolean isDigit(char c) {
            return c >= '0' && c <= '9';
        }
    }

    public static final class JsonParseException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public JsonParseException(String message, int position) {
            super("Invalid JSON at position " + position + ": " + message);
        }
    }
}
