package com.github.highcumontoa.springaccessguardjava.tests;

import com.github.highcumontoa.springaccessguardjava.security.decision.AccessDecision;
import com.github.highcumontoa.springaccessguardjava.security.decision.LoginDecision;
import com.github.highcumontoa.springaccessguardjava.security.decision.RejectionReason;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

/**
 * Role authorization invariants:
 * <ul>
 *   <li>unauthenticated requests get token-specific reasons (401 family),
 *       never FORBIDDEN — the two denials are distinguishable;</li>
 *   <li>an authenticated account lacking the role gets FORBIDDEN;</li>
 *   <li>role changes affect already-issued tokens immediately (live roles),
 *       and repeated decisions for one request agree (no mid-request flip).</li>
 * </ul>
 */
class AuthorizationTest {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationTest.class);

    @Test
    void unauthenticatedIsNotForbidden() {
        GuardTestFactory.Harness h = GuardTestFactory.build();

        assertReason(h, null, "admin", RejectionReason.MISSING_TOKEN);
        assertReason(h, "garbage", "admin", RejectionReason.MALFORMED_TOKEN);

        // A valid token for an account, then tamper with it: BAD_SIGNATURE,
        // still not FORBIDDEN.
        String token = login(h, "user", "user123");
        String tampered = token.substring(0, token.length() - 1)
                + (token.endsWith("A") ? "Z" : "A");
        assertReason(h, tampered, "admin", RejectionReason.BAD_SIGNATURE);
    }

    @Test
    void authenticatedButLackingRoleIsFORBIDDEN() {
        GuardTestFactory.Harness h = GuardTestFactory.build();
        String token = login(h, "user", "user123");

        // user role passes
        AccessDecision ok = h.guard().authorize(token, "user", GuardTestFactory.SOURCE_A);
        assertInstanceOf(AccessDecision.Allowed.class, ok);
        log.info("input: user token, requiredRole=user -> ALLOWED roles={}",
                ((AccessDecision.Allowed) ok).roles());

        // admin role denied with FORBIDDEN (authenticated, distinct from 401)
        AccessDecision denied = h.guard().authorize(token, "admin", GuardTestFactory.SOURCE_A);
        AccessDecision.Denied d = assertInstanceOf(AccessDecision.Denied.class, denied);
        assertEquals(RejectionReason.FORBIDDEN, d.reason());
        log.info("input: user token, requiredRole=admin -> reason={} basis='{}'",
                d.reason(), d.detail());
    }

    @Test
    void roleChangeTakesEffectOnExistingTokenImmediately() {
        GuardTestFactory.Harness h = GuardTestFactory.build();
        String token = login(h, "user", "user123");

        // before: forbidden
        assertReason(h, token, "admin", RejectionReason.FORBIDDEN);

        // promote: same token, decision must change immediately
        boolean updated = h.accounts().updateRoles("user", Set.of("user", "admin"));
        assertEquals(true, updated);
        log.info("basis: roles of 'user' updated to [user, admin]; reusing same token");

        AccessDecision after = h.guard().authorize(token, "admin", GuardTestFactory.SOURCE_A);
        assertInstanceOf(AccessDecision.Allowed.class, after,
                "live roles must make the existing token pass");
        log.info("after promotion -> ALLOWED roles={}", ((AccessDecision.Allowed) after).roles());

        // demote again
        h.accounts().updateRoles("user", Set.of("user"));
        assertReason(h, token, "admin", RejectionReason.FORBIDDEN);
        log.info("after demotion -> FORBIDDEN again with the same still-valid token");
    }

    @Test
    void repeatedDecisionsForOneRequestAreConsistent() {
        GuardTestFactory.Harness h = GuardTestFactory.build();
        String token = login(h, "admin", "admin123");
        // Simulate framework + business code both asking within one request.
        for (int i = 0; i < 10; i++) {
            AccessDecision d = h.guard().authorize(token, "admin", GuardTestFactory.SOURCE_A);
            assertInstanceOf(AccessDecision.Allowed.class, d,
                    "decision must not flip between calls");
        }
        log.info("basis: 10 identical authorize calls for one request all ALLOWED");
    }

    private String login(GuardTestFactory.Harness h, String u, String p) {
        LoginDecision decision = h.guard().login(u, p, GuardTestFactory.SOURCE_A);
        return ((LoginDecision.Success) decision).token();
    }

    private void assertReason(GuardTestFactory.Harness h, String token, String role,
                              RejectionReason expected) {
        AccessDecision decision = h.guard().authorize(token, role, GuardTestFactory.SOURCE_A);
        AccessDecision.Denied denied = assertInstanceOf(AccessDecision.Denied.class, decision,
                "expected a denial");
        log.info("input: tokenPresent={}, requiredRole='{}' -> reason={} basis='{}'",
                token != null, role, denied.reason(), denied.detail());
        assertEquals(expected, denied.reason());
    }
}
