package com.saytu.core.security;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SensitiveValueTest {

    @Test
    void toStringNeverRevealsValue() {
        SensitiveValue v = SensitiveValue.of("glpat-supersecret");
        assertEquals(SensitiveValue.MASK, v.toString());
        assertFalse(String.valueOf(v).contains("supersecret"));
        assertFalse(("token=" + v).contains("supersecret"));
    }

    @Test
    void revealReturnsValueUntilDestroyed() {
        SensitiveValue v = SensitiveValue.of("abc");
        assertEquals("abc", v.reveal());
        v.close();
        assertTrue(v.isDestroyed());
        assertThrows(IllegalStateException.class, v::reveal);
    }

    @Test
    void charArrayInputIsCopied() {
        char[] source = {'x', 'y'};
        SensitiveValue v = SensitiveValue.of(source);
        source[0] = 'z';
        assertEquals("xy", v.reveal());
    }

    @Test
    void equalityIsByIdentity() {
        assertNotEquals(SensitiveValue.of("a"), SensitiveValue.of("a"));
    }

    @Test
    void blankDetection() {
        assertTrue(SensitiveValue.of("  ").isBlank());
        assertFalse(SensitiveValue.of(" t ").isBlank());
    }
}
