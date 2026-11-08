package com.saytu.app.scan;

import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * When the stored formula is newer than the latest scores (upgrade to formula v2, or a formula changed
 * while the worker was down), the worker rescores every audited branch from the stored results once at
 * start-up: no repository is cloned or analysed again. A migration that changes stored findings asks
 * for the same rescore through the one-shot setting {@code scoring.rescore}.
 */
@Component
@ConditionalOnProperty(prefix = "saytu.scan.worker", name = "enabled", havingValue = "true")
public class ScoreUpgrade {

    private static final Logger log = LoggerFactory.getLogger(ScoreUpgrade.class);

    private final ScoreService scores;

    public ScoreUpgrade(ScoreService scores) {
        this.scores = scores;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void rescoreIfFormulaChanged() {
        String current = scores.formula().version();
        Optional<String> reason = scores.latestFormulaVersion().filter(v -> !v.equals(current))
                .map(previous -> "scoring formula changed (" + previous + " -> " + current + ")")
                .or(() -> scores.consumeRescoreRequest().map(r -> "requested by a migration: " + r));
        reason.ifPresent(r -> {
            log.info("Rescoring every audited branch from stored results: {}", r);
            int n = scores.rescore(null, null);
            log.info("Rescored {} branch(es) with formula {}", n, current);
        });
        scores.consumeRescoreRequest(); // a request is satisfied by any full rescore
    }
}
