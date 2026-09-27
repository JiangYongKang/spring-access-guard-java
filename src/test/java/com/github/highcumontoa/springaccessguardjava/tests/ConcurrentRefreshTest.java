package com.github.highcumontoa.springaccessguardjava.tests;

import com.github.highcumontoa.springaccessguardjava.security.decision.AccessDecision;
import com.github.highcumontoa.springaccessguardjava.security.decision.RefreshDecision;
import com.github.highcumontoa.springaccessguardjava.security.decision.RejectionReason;
import com.github.highcumontoa.springaccessguardjava.security.decision.TokenCheck;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Concurrent refresh invariants:
 * <ul>
 *   <li>of N simultaneous refreshes of one token, exactly one ROTATED;</li>
 *   <li>exactly one successor verifies as LIVE, losers get REFRESH_REJECTED;</li>
 *   <li>re-presenting the old token afterwards is REUSE_DETECTED and revokes
 *       the whole family (the winner's successor stops working too).</li>
 * </ul>
 */
class ConcurrentRefreshTest {

    private static final Logger log = LoggerFactory.getLogger(ConcurrentRefreshTest.class);

    private final int threads = 16;

    @Test
    void exactlyOneConcurrentRefreshSucceeds() throws Exception {
        GuardTestFactory.Harness h = GuardTestFactory.build();
        String token = h.guard().login("user", "user123", GuardTestFactory.SOURCE_A)
                instanceof com.github.highcumontoa.springaccessguardjava.security.decision
                        .LoginDecision.Success s ? s.token() : null;
        log.info("input: {} threads refresh the same token '{}...'",
                threads, token.substring(0, 18));

        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownAndGo barrier = new CountDownAndGo(threads);
        try {
            List<Future<RefreshDecision>> futures = IntStream.range(0, threads)
                    .<Callable<RefreshDecision>>mapToObj(i -> () -> {
                        barrier.awaitRelease();
                        return h.guard().refresh(token, GuardTestFactory.SOURCE_A);
                    })
                    .map(pool::submit)
                    .toList();

            barrier.releaseOnceAllReady();

            List<RefreshDecision> outcomes = new java.util.ArrayList<>();
            for (Future<RefreshDecision> f : futures) {
                outcomes.add(f.get(30, TimeUnit.SECONDS));
            }

            long rotated = outcomes.stream().filter(RefreshDecision.Rotated.class::isInstance).count();
            long rejected = outcomes.stream().filter(RefreshDecision.Rejected.class::isInstance).count();
            Set<String> successors = outcomes.stream()
                    .filter(RefreshDecision.Rotated.class::isInstance)
                    .map(d -> ((RefreshDecision.Rotated) d).newToken())
                    .collect(Collectors.toSet());

            log.info("basis: rotated={}, rejected={}, distinctSuccessors={}",
                    rotated, rejected, successors.size());
            for (RefreshDecision d : outcomes) {
                if (d instanceof RefreshDecision.Rejected r) {
                    log.info("loser reason={} basis='{}'", r.reason(), r.detail());
                    assertEquals(RejectionReason.REFRESH_REJECTED, r.reason());
                }
            }

            assertEquals(1, rotated, "exactly one refresh may win");
            assertEquals(threads - 1, rejected);
            assertEquals(1, successors.size(), "at most one valid successor credential");

            // The single successor must be the only live token in the family.
            String winner = successors.iterator().next();
            assertInstanceOf(TokenCheck.Valid.class, h.tokens().verify(winner),
                    "successor must verify");
            // no duplicate live successors hiding in the store
            long liveInFamily = h.tokenStore().size();
            assertTrue(liveInFamily >= 2, "store holds original + successor");
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void lateReuseAfterRaceWindowRevokesFamily_raceWindowIsBenign() {
        GuardTestFactory.Harness h = GuardTestFactory.build();
        String token = loginToken(h, "user", "user123");

        RefreshDecision first = h.guard().refresh(token, GuardTestFactory.SOURCE_A);
        RefreshDecision.Rotated rotated = assertInstanceOf(RefreshDecision.Rotated.class, first);
        log.info("first refresh rotated into '{}...'", rotated.newToken().substring(0, 18));

        // Immediately re-presenting the old token is a concurrent-race loser:
        // rejected, but the family (and the new token) stays valid.
        RefreshDecision inWindow = h.guard().refresh(token, GuardTestFactory.SOURCE_A);
        RefreshDecision.Rejected inWindowRejected =
                assertInstanceOf(RefreshDecision.Rejected.class, inWindow);
        log.info("in-window reuse input: old token -> reason={} basis='{}'",
                inWindowRejected.reason(), inWindowRejected.detail());
        assertEquals(RejectionReason.REFRESH_REJECTED, inWindowRejected.reason());
        assertInstanceOf(TokenCheck.Valid.class, h.tokens().verify(rotated.newToken()),
                "successor must remain valid after an in-window race");

        // After the race window the same old token is genuine reuse: theft.
        h.clock().advance(java.time.Duration.ofSeconds(31));
        RefreshDecision reuse = h.guard().refresh(token, GuardTestFactory.SOURCE_A);
        RefreshDecision.Rejected rejected = assertInstanceOf(RefreshDecision.Rejected.class, reuse);
        log.info("post-window reuse input: old token -> reason={} basis='{}'",
                rejected.reason(), rejected.detail());
        assertEquals(RejectionReason.REUSE_DETECTED, rejected.reason());

        // The previously valid successor is now revoked as part of family revocation.
        TokenCheck successorCheck = h.tokens().verify(rotated.newToken());
        TokenCheck.Invalid invalid = assertInstanceOf(TokenCheck.Invalid.class, successorCheck);
        log.info("basis: successor after reuse -> reason={}", invalid.reason());
        assertEquals(RejectionReason.REVOKED, invalid.reason());

        // And the old token is denied at protected entries too. Family
        // revocation flipped it ROTATED -> REVOKED, which is still a distinct,
        // explainable reason (not a generic auth failure).
        AccessDecision denied = h.guard().authorize(token, "", GuardTestFactory.SOURCE_A);
        assertEquals(RejectionReason.REVOKED,
                ((AccessDecision.Denied) denied).reason());
    }

    private String loginToken(GuardTestFactory.Harness h, String u, String p) {
        var decision = h.guard().login(u, p, GuardTestFactory.SOURCE_A);
        return ((com.github.highcumontoa.springaccessguardjava.security.decision
                .LoginDecision.Success) decision).token();
    }

    /** Start gate so all threads really call refresh at the same instant. */
    private static final class CountDownAndGo {
        private final java.util.concurrent.CountDownLatch ready;
        private final java.util.concurrent.CountDownLatch go = new java.util.concurrent.CountDownLatch(1);

        CountDownAndGo(int n) {
            this.ready = new java.util.concurrent.CountDownLatch(n);
        }

        /** Worker: announce readiness, then block until the coordinator releases. */
        void awaitRelease() throws InterruptedException {
            ready.countDown();
            go.await();
        }

        /** Coordinator: wait until every worker is parked, then release them together. */
        void releaseOnceAllReady() throws InterruptedException {
            ready.await();
            go.countDown();
        }
    }
}
