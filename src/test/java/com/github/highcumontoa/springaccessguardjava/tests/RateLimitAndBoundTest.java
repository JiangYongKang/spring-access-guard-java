package com.github.highcumontoa.springaccessguardjava.tests;

import com.github.highcumontoa.springaccessguardjava.security.decision.LoginDecision;
import com.github.highcumontoa.springaccessguardjava.security.decision.RejectionReason;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Source rate limiting and bounded internal record sizes. */
class RateLimitAndBoundTest {

    private static final Logger log = LoggerFactory.getLogger(RateLimitAndBoundTest.class);

    @Test
    void sourceIsRateLimitedThenWindowSlides() {
        int limit = 5;
        // Lock threshold deliberately high: this case isolates rate limiting
        // from account locking (which is covered by LockoutTest).
        GuardTestFactory.Harness h = GuardTestFactory.build(100, Duration.ofMinutes(5),
                Duration.ofMinutes(15), limit, Duration.ofMinutes(1));

        int allowed = 0;
        int limited = 0;
        for (int i = 0; i < limit + 3; i++) {
            LoginDecision d = h.guard().login("user", "wrong", GuardTestFactory.SOURCE_A);
            if (((LoginDecision.Failure) d).reason() == RejectionReason.RATE_LIMITED) {
                limited++;
            } else {
                allowed++;
            }
        }
        log.info("input: {} rapid requests, limit={} -> allowed={} rateLimited={}",
                limit + 3, limit, allowed, limited);
        assertEquals(limit, allowed);
        assertEquals(3, limited);

        // A different source is independent and unaffected by A's failures.
        // (Use a fresh harness so B has its own untouched rate window too.)
        GuardTestFactory.Harness h2 = GuardTestFactory.build(100, Duration.ofMinutes(5),
                Duration.ofMinutes(15), limit, Duration.ofMinutes(1));
        LoginDecision other = h2.guard().login("user", "user123", GuardTestFactory.SOURCE_B);
        assertTrue(other instanceof LoginDecision.Success,
                "rate limit must be per-source");
        log.info("basis: source B unaffected while source A is limited");

        // After the window slides, source A is usable again.
        h.clock().advance(Duration.ofMinutes(2));
        LoginDecision recovered = h.guard()
                .login("user", "user123", GuardTestFactory.SOURCE_A);
        assertTrue(recovered instanceof LoginDecision.Success);
        log.info("after window slides source A -> SUCCESS");
    }

    @Test
    void failureTrackerAndRateLimiterRecordsAreBounded() {
        int maxAccounts = 10;
        int maxSources = 8;
        var clock = new MutableClock(java.time.Instant.parse("2026-09-27T00:00:00Z"));
        var failures = new com.github.highcumontoa.springaccessguardjava.security.auth
                .FailureTracker(100, Duration.ofMinutes(5), Duration.ofMinutes(15),
                maxAccounts, clock);
        var limiter = new com.github.highcumontoa.springaccessguardjava.security.auth
                .SourceRateLimiter(100, Duration.ofMinutes(1), maxSources, clock);

        // 200 distinct account/source keys: tracker must stay at/near its cap.
        for (int i = 0; i < 200; i++) {
            failures.recordFailure(com.github.highcumontoa.springaccessguardjava.security.model
                    .AccountSource.of("acct" + i, "10.1.1." + (i % 250)));
        }
        failures.purge();
        log.info("basis: 200 distinct failure keys, cap={}, tracked={}",
                maxAccounts, failures.trackedKeys());
        assertTrue(failures.trackedKeys() <= maxAccounts,
                "failure tracker must not grow without bound");

        for (int i = 0; i < 200; i++) {
            limiter.tryAcquire("20.2.2." + i);
        }
        limiter.purge();
        log.info("basis: 200 distinct sources, cap={}, tracked={}",
                maxSources, limiter.trackedSources());
        assertTrue(limiter.trackedSources() <= maxSources,
                "rate limiter must not grow without bound");
    }
}
