package com.saytu.git.provider;

import com.saytu.core.git.GitProvider.Page;
import com.saytu.core.git.GitProviderException;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PageCollectorTest {

    @Test
    void collectsEveryPage() {
        var r = PageCollector.<Integer>collect(req -> req.cursor() == null
                ? new Page<>(List.of(1, 2), "2", null)
                : new Page<>(List.of(3), null, null), 100);
        assertEquals(List.of(1, 2, 3), r.items());
        assertTrue(r.complete());
    }

    @Test
    void stopsAtTheLimit() {
        AtomicInteger calls = new AtomicInteger();
        var r = PageCollector.<Integer>collect(req -> {
            calls.incrementAndGet();
            return new Page<>(List.of(1, 2, 3), String.valueOf(calls.get() + 1), null);
        }, 5);
        assertEquals(5, r.items().size());
        assertTrue(r.truncated());
        assertEquals(2, calls.get());
    }

    @Test
    void keepsPartialResultsOnError() {
        var r = PageCollector.<Integer>collect(req -> {
            if (req.cursor() != null) {
                throw new GitProviderException(GitProviderException.Kind.RATE_LIMITED, "slow down");
            }
            return new Page<>(List.of(1), "2", null);
        }, 100);
        assertEquals(List.of(1), r.items());
        assertEquals(GitProviderException.Kind.RATE_LIMITED, r.error().kind());
        assertFalse(r.complete());
    }

    @Test
    void detectsPaginationLoops() {
        var r = PageCollector.<Integer>collect(req -> new Page<>(List.of(1), "same", null), 1000);
        assertEquals(2, r.items().size());
        assertEquals(GitProviderException.Kind.UNEXPECTED_RESPONSE, r.error().kind());
        assertNull(PageCollector.<Integer>collect(req -> new Page<>(List.of(), null, 0), 10).error());
    }
}
