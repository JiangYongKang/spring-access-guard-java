package com.github.highcumontoa.springaccessguardjava.tests;

import com.github.highcumontoa.springaccessguardjava.security.AccessGuard;
import com.github.highcumontoa.springaccessguardjava.security.auth.FailureTracker;
import com.github.highcumontoa.springaccessguardjava.security.auth.SourceRateLimiter;
import com.github.highcumontoa.springaccessguardjava.security.authorization.Authorizer;
import com.github.highcumontoa.springaccessguardjava.security.crypto.PasswordHasher;
import com.github.highcumontoa.springaccessguardjava.security.model.Account;
import com.github.highcumontoa.springaccessguardjava.security.store.AccountStore;
import com.github.highcumontoa.springaccessguardjava.security.token.HmacTokenSigner;
import com.github.highcumontoa.springaccessguardjava.security.token.LocalTokenStore;
import com.github.highcumontoa.springaccessguardjava.security.token.TokenService;

import java.time.Duration;
import java.time.Instant;
import java.util.Set;

/** Builds a fully wired {@link AccessGuard} for unit tests with a controllable clock. */
public final class GuardTestFactory {

    public static final String SOURCE_A = "10.0.0.1";
    public static final String SOURCE_B = "10.0.0.2";

    private GuardTestFactory() {
    }

    public record Harness(AccessGuard guard,
                          AccountStore accounts,
                          TokenService tokens,
                          LocalTokenStore tokenStore,
                          FailureTracker failures,
                          SourceRateLimiter rateLimiter,
                          MutableClock clock,
                          int lockThreshold,
                          Duration lockDuration) {

        public void seedDefaultUsers(PasswordHasher hasher) {
            accounts.put(new Account("admin", hasher.hash("admin123"),
                    Set.of("admin", "user"), true));
            accounts.put(new Account("user", hasher.hash("user123"),
                    Set.of("user"), true));
        }
    }

    public static Harness build() {
        return build(5, Duration.ofMinutes(5), Duration.ofMinutes(15),
                60, Duration.ofMinutes(1));
    }

    public static Harness build(int lockThreshold, Duration lockDuration,
                                Duration failureWindow, int rateLimit, Duration rateWindow) {
        MutableClock clock = new MutableClock(Instant.parse("2026-09-27T00:00:00Z"));
        AccountStore accounts = new AccountStore();
        LocalTokenStore tokenStore = new LocalTokenStore();
        HmacTokenSigner signer = new HmacTokenSigner("test-secret-which-is-long-enough-32b");
        TokenService tokens = new TokenService(signer, tokenStore, Duration.ofMinutes(30), clock);
        Authorizer authorizer = new Authorizer(accounts);
        PasswordHasher hasher = new PasswordHasher();
        FailureTracker failures = new FailureTracker(lockThreshold, lockDuration,
                failureWindow, 1000, clock);
        SourceRateLimiter rateLimiter = new SourceRateLimiter(rateLimit, rateWindow, 1000, clock);
        AccessGuard guard = new AccessGuard(accounts, tokens, authorizer, hasher,
                failures, rateLimiter);
        Harness harness = new Harness(guard, accounts, tokens, tokenStore, failures,
                rateLimiter, clock, lockThreshold, lockDuration);
        harness.seedDefaultUsers(hasher);
        return harness;
    }
}
