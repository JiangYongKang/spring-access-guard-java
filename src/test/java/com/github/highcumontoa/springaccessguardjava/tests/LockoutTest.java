package com.github.highcumontoa.springaccessguardjava.tests;

import com.github.highcumontoa.springaccessguardjava.security.decision.AccessDecision;
import com.github.highcumontoa.springaccessguardjava.security.decision.LoginDecision;
import com.github.highcumontoa.springaccessguardjava.security.decision.RejectionReason;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Failure counting, temporary lock and automatic recovery.
 */
class LockoutTest {

    private static final Logger log = LoggerFactory.getLogger(LockoutTest.class);
    private static final int THRESHOLD = 3;

    @Test
    void thresholdLocksAndCorrectCredentialsAreRejectedThenRecover() {
        GuardTestFactory.Harness h = GuardTestFactory.build(THRESHOLD,
                Duration.ofMinutes(5), Duration.ofMinutes(15), 10_000, Duration.ofMinutes(1));

        for (int i = 1; i <= THRESHOLD; i++) {
            LoginDecision d = h.guard().login("user", "wrong", GuardTestFactory.SOURCE_A);
            RejectionReason reason = ((LoginDecision.Failure) d).reason();
            log.info("failure #{} input: wrong password -> reason={} (count={})",
                    i, reason, h.failures().failureCount(
                            com.github.highcumontoa.springaccessguardjava.security.model
                                    .AccountSource.of("user", GuardTestFactory.SOURCE_A)));
            assertEquals(RejectionReason.BAD_CREDENTIALS, reason);
        }

        // Correct credentials while locked: still rejected with LOCKED.
        LoginDecision locked = h.guard().login("user", "user123", GuardTestFactory.SOURCE_A);
        RejectionReason lockedReason = ((LoginDecision.Failure) locked).reason();
        log.info("input: CORRECT password while locked -> reason={} basis='{}'",
                lockedReason, ((LoginDecision.Failure) locked).detail());
        assertEquals(RejectionReason.ACCOUNT_LOCKED, lockedReason);

        // Same for an already-valid token from the locked key.
        String token = ((LoginDecision.Success) h.guard()
                .login("user", "user123", GuardTestFactory.SOURCE_B)).token();
        AccessDecision apiDenied = h.guard().authorize(token, "user", GuardTestFactory.SOURCE_A);
        assertEquals(RejectionReason.ACCOUNT_LOCKED,
                ((AccessDecision.Denied) apiDenied).reason());
        log.info("input: valid token from locked source -> ACCOUNT_LOCKED (abuse wins)");

        // Advance past the lock: automatic recovery with the correct password.
        h.clock().advance(Duration.ofMinutes(6));
        LoginDecision after = h.guard().login("user", "user123", GuardTestFactory.SOURCE_A);
        assertInstanceOf(LoginDecision.Success.class, after,
                "lock must auto-expire without any reset call");
        log.info("after 6 minutes input: correct password -> SUCCESS (auto recovered)");
    }

    @Test
    void oneSourceCannotLockTheSameAccountAtAnotherSource() {
        GuardTestFactory.Harness h = GuardTestFactory.build(THRESHOLD,
                Duration.ofMinutes(5), Duration.ofMinutes(15), 10_000, Duration.ofMinutes(1));

        for (int i = 0; i < THRESHOLD; i++) {
            h.guard().login("user", "wrong", GuardTestFactory.SOURCE_A);
        }
        RejectionReason attacker = ((LoginDecision.Failure) h.guard()
                .login("user", "user123", GuardTestFactory.SOURCE_A)).reason();
        assertEquals(RejectionReason.ACCOUNT_LOCKED, attacker);

        // Another source for the same account is unaffected.
        LoginDecision legit = h.guard().login("user", "user123", GuardTestFactory.SOURCE_B);
        assertInstanceOf(LoginDecision.Success.class, legit);
        log.info("basis: abusive source A locked; legitimate source B -> SUCCESS");

        // Another account from the abusive source is also unaffected.
        LoginDecision otherAccount = h.guard()
                .login("admin", "admin123", GuardTestFactory.SOURCE_A);
        assertInstanceOf(LoginDecision.Success.class, otherAccount);
        log.info("basis: account 'admin' from locked source A -> SUCCESS (keys are per account)");
    }

    @Test
    void failuresAgeOutOfTheSlidingWindow() {
        GuardTestFactory.Harness h = GuardTestFactory.build(THRESHOLD,
                Duration.ofMinutes(5), Duration.ofMinutes(2), 10_000, Duration.ofMinutes(1));

        h.guard().login("user", "wrong", GuardTestFactory.SOURCE_A);
        h.guard().login("user", "wrong", GuardTestFactory.SOURCE_A);
        h.clock().advance(Duration.ofMinutes(3)); // outside the 2-minute failure window
        h.guard().login("user", "wrong", GuardTestFactory.SOURCE_A);

        LoginDecision decision = h.guard()
                .login("user", "user123", GuardTestFactory.SOURCE_A);
        assertInstanceOf(LoginDecision.Success.class, decision,
                "aged-out failures must not accumulate toward the lock");
        log.info("basis: failures older than the window forgotten; correct login -> SUCCESS");
    }

    @Test
    void concurrentFailuresAreCountedWithoutLoss() throws Exception {
        int attempts = 200;
        GuardTestFactory.Harness h = GuardTestFactory.build(attempts,
                Duration.ofMinutes(5), Duration.ofMinutes(15), 10_000, Duration.ofMinutes(1));
        var key = com.github.highcumontoa.springaccessguardjava.security.model
                .AccountSource.of("user", GuardTestFactory.SOURCE_A);

        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(attempts);
        try {
            List<Future<?>> futures = new ArrayList<>();
            for (int i = 0; i < attempts; i++) {
                futures.add(pool.submit(() -> {
                    start.await();
                    h.guard().login("user", "wrong", GuardTestFactory.SOURCE_A);
                    done.countDown();
                    return null;
                }));
            }
            start.countDown();
            assertTrue(done.await(30, TimeUnit.SECONDS));
            for (Future<?> f : futures) {
                f.get();
            }
        } finally {
            pool.shutdownNow();
        }

        int counted = h.failures().failureCount(key);
        log.info("input: {} concurrent bad logins -> counted failures={}", attempts, counted);
        assertEquals(attempts, counted, "no failure increment may be lost under concurrency");
    }
}
