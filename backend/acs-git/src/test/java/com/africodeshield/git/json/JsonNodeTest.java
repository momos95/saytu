package com.africodeshield.git.json;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JsonNodeTest {

    @Test
    void parsesNestedDocument() {
        JsonNode n = JsonNode.parse("""
                {"id": 42, "username": "awa", "bot": false, "scopes": ["read_api", "read_repository"],
                 "expires_at": null, "ratio": -1.5e2, "owner": {"login": "o\\u00e9\\n"}}""");
        assertEquals(42, n.get("id").asLong(0));
        assertEquals("awa", n.get("username").asText());
        assertFalse(n.get("bot").asBoolean(true));
        assertEquals(List.of("read_api", "read_repository"), n.get("scopes").textElements());
        assertTrue(n.get("expires_at").isNull());
        assertTrue(n.get("expires_at").isAbsent());
        assertEquals("-150", n.get("ratio").asText());
        assertEquals("oé\n", n.get("owner").get("login").asText());
    }

    @Test
    void navigationNeverThrows() {
        JsonNode n = JsonNode.parse("[1,{\"a\":[]}]");
        assertTrue(n.get("x").isMissing());
        assertTrue(n.get(5).isMissing());
        assertTrue(n.get(1).get("a").get(0).get("b").isMissing());
        assertNull(n.get("x").asText());
        assertEquals(7, n.get(9).asLong(7));
        assertEquals(2, n.size());
        assertTrue(JsonNode.MISSING.text("a").isEmpty());
    }

    @Test
    void rejectsInvalidJson() {
        for (String bad : List.of("", "{", "{\"a\":}", "[1,]", "{'a':1}", "01", "1.", "tru", "\"\u0001\"",
                "\"\\x\"", "{} extra", "[1 2]", "\"unterminated", "-", "1e")) {
            assertThrows(JsonNode.JsonParseException.class, () -> JsonNode.parse(bad), bad);
        }
    }

    @Test
    void boundsNestingDepth() {
        String deep = "[".repeat(JsonNode.MAX_DEPTH + 2) + "]".repeat(JsonNode.MAX_DEPTH + 2);
        assertThrows(JsonNode.JsonParseException.class, () -> JsonNode.parse(deep));
        String ok = "[".repeat(10) + "]".repeat(10);
        assertTrue(JsonNode.parse(ok).isArray());
    }

    @Test
    void numbersAndLongsEdgeCases() {
        assertEquals(-1, JsonNode.parse("1.5").asLong(-1));
        assertEquals(12, JsonNode.parse("\"12\"").asLong(0));
        assertEquals(0, JsonNode.parse("0").asLong(-1));
        assertEquals("true", JsonNode.parse("true").asText());
    }
}
