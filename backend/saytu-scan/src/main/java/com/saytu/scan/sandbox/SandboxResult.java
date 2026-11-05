package com.saytu.scan.sandbox;

import java.time.Duration;

/**
 * Outcome of one sandboxed process.
 *
 * @param exitCode   process exit code; meaningless when {@code timedOut}
 * @param timedOut   the wall-clock limit was reached and the process tree was killed
 * @param memoryExceeded the resident memory of the process tree went over the limit and the tree was killed
 * @param peakRssBytes   highest sampled resident memory of the process tree (0 if not measured)
 * @param duration   wall-clock duration
 * @param stdoutTail last bytes of standard output, secrets masked
 * @param stderrTail last bytes of standard error, secrets masked
 */
public record SandboxResult(int exitCode, boolean timedOut, boolean memoryExceeded, long peakRssBytes,
                            Duration duration, String stdoutTail, String stderrTail) {

    /** The process ran to completion (neither timed out nor killed for memory). */
    public boolean completed() {
        return !timedOut && !memoryExceeded;
    }

    /** Short diagnostic for error messages: the end of stderr, or of stdout when stderr is empty. */
    public String diagnostic(int maxChars) {
        String text = stderrTail != null && !stderrTail.isBlank() ? stderrTail : stdoutTail;
        if (text == null) {
            return "";
        }
        text = text.strip();
        return text.length() <= maxChars ? text : "…" + text.substring(text.length() - maxChars + 1);
    }
}
