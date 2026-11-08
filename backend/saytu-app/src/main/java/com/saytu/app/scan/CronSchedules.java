package com.saytu.app.scan;

import org.springframework.scheduling.support.CronExpression;

import java.time.DateTimeException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Locale;
import java.util.Optional;

/**
 * Cron expressions of audit schedules. Accepts the 5-field Unix form ("0 2 * * 1-5"), the 6-field
 * Spring form ("0 0 2 * * MON-FRI") and the macros (@daily, @weekly…); stores the 6-field form.
 * A schedule may not fire more often than every {@link #MIN_INTERVAL_MINUTES} minutes.
 */
final class CronSchedules {

    static final int MIN_INTERVAL_MINUTES = 15;

    private CronSchedules() {
    }

    /** 6-field form of a valid expression; IllegalArgumentException with a user-facing message otherwise. */
    static String normalize(String expression) {
        if (expression == null || expression.isBlank()) {
            throw new IllegalArgumentException("Expression cron obligatoire");
        }
        String e = expression.strip().replaceAll("\\s+", " ");
        if (e.length() > 120) {
            throw new IllegalArgumentException("Expression cron trop longue");
        }
        if (!e.startsWith("@") && e.split(" ").length == 5) {
            e = "0 " + e;
        }
        if (!CronExpression.isValidExpression(e)) {
            throw new IllegalArgumentException("Expression cron invalide : " + expression
                    + " (exemple : « 0 2 * * 1-5 » = 2 h du lundi au vendredi)");
        }
        return e.startsWith("@") ? e.toLowerCase(Locale.ROOT) : e;
    }

    static ZoneId zone(String timeZone) {
        try {
            return ZoneId.of(timeZone == null || timeZone.isBlank() ? "UTC" : timeZone.strip());
        } catch (DateTimeException e) {
            throw new IllegalArgumentException("Fuseau horaire inconnu : " + timeZone);
        }
    }

    /** Next firing strictly after {@code after}, in the schedule's time zone. */
    static Optional<Instant> next(String expression, ZoneId zone, Instant after) {
        ZonedDateTime next = CronExpression.parse(expression).next(after.atZone(zone));
        return Optional.ofNullable(next).map(ZonedDateTime::toInstant);
    }

    /** Refuses schedules firing more often than every 15 minutes (checked on the next two firings). */
    static void checkInterval(String expression, ZoneId zone, Instant now) {
        Instant first = next(expression, zone, now).orElseThrow(() ->
                new IllegalArgumentException("Cette expression ne se déclenche jamais"));
        Instant second = next(expression, zone, first).orElse(null);
        if (second != null && java.time.Duration.between(first, second).toMinutes() < MIN_INTERVAL_MINUTES) {
            throw new IllegalArgumentException("Un audit planifié ne peut pas se déclencher plus d'une fois toutes les "
                    + MIN_INTERVAL_MINUTES + " minutes");
        }
    }
}
