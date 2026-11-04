package com.africodeshield.git.provider;

import com.africodeshield.core.git.GitProvider.Page;
import com.africodeshield.core.git.GitProvider.PageRequest;
import com.africodeshield.core.git.GitProviderException;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Function;

/**
 * Walks every page of a provider listing, with safety limits.
 * <ul>
 *   <li>stops at {@code maxItems} ({@link Result#truncated()});</li>
 *   <li>stops if a platform returns the same cursor twice (pagination loop);</li>
 *   <li>on a provider error, keeps what was already fetched and reports the error
 *       ({@link Result#error()}): a rate limit hit on page 40 does not lose pages 1-39.</li>
 * </ul>
 */
public final class PageCollector {

    public static final int PAGE_SIZE = 100;

    private PageCollector() {
    }

    public record Result<T>(List<T> items, boolean truncated, GitProviderException error) {
        public Result {
            items = List.copyOf(items);
        }

        public boolean complete() {
            return !truncated && error == null;
        }
    }

    public static <T> Result<T> collect(Function<PageRequest, Page<T>> fetch, int maxItems) {
        List<T> items = new ArrayList<>();
        Set<String> seenCursors = new HashSet<>();
        String cursor = null;
        try {
            while (true) {
                Page<T> page = fetch.apply(new PageRequest(cursor, PAGE_SIZE));
                for (T item : page.items()) {
                    if (items.size() >= maxItems) {
                        return new Result<>(items, true, null);
                    }
                    items.add(item);
                }
                if (!page.hasNext()) {
                    return new Result<>(items, false, null);
                }
                if (!seenCursors.add(page.nextCursor())) {
                    return new Result<>(items, false, new GitProviderException(GitProviderException.Kind.UNEXPECTED_RESPONSE,
                            "The platform returned the same page twice; listing stopped"));
                }
                if (items.size() >= maxItems) {
                    return new Result<>(items, true, null);
                }
                cursor = page.nextCursor();
            }
        } catch (GitProviderException e) {
            return new Result<>(items, false, e);
        }
    }
}
