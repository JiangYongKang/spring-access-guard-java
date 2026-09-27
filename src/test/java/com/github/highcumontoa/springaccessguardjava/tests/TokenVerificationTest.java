package com.github.highcumontoa.springaccessguardjava.tests;

import com.github.highcumontoa.springaccessguardjava.security.decision.RejectionReason;
import com.github.highcumontoa.springaccessguardjava.security.decision.TokenCheck;
import com.github.highcumontoa.springaccessguardjava.security.token.HmacTokenSigner;
import com.github.highcumontoa.springaccessguardjava.security.token.LocalTokenStore;
import com.github.highcumontoa.springaccessguardjava.security.token.TokenService;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

/**
 * Token verification must keep malformed / tampered / expired / revoked /
 * unknown apart. Each test prints its input and the decision basis.
 */
class TokenVerificationTest {

    private static final Logger log = LoggerFactory.getLogger(TokenVerificationTest.class);

    private TokenCheck.Invalid reject(GuardTestFactory.Harness h, String raw, String label) {
        TokenCheck check = h.tokens().verify(raw);
        TokenCheck.Invalid invalid = assertInstanceOf(TokenCheck.Invalid.class, check,
                label + " should be rejected");
        log.info("[{}] input token='{}' -> reason={} basis='{}'",
                label, abbreviate(raw), invalid.reason(), invalid.detail());
        return invalid;
    }

    @Test
    void missingTokenIsMISSING_TOKEN() {
        GuardTestFactory.Harness h = GuardTestFactory.build();
        assertEquals(RejectionReason.MISSING_TOKEN, reject(h, null, "null").reason());
        assertEquals(RejectionReason.MISSING_TOKEN, reject(h, "  ", "blank").reason());
    }

    @Test
    void structurallyWrongTokenIsMALFORMED() {
        GuardTestFactory.Harness h = GuardTestFactory.build();
        assertEquals(RejectionReason.MALFORMED_TOKEN,
                reject(h, "no-dot-separator", "no-dot").reason());
        assertEquals(RejectionReason.MALFORMED_TOKEN,
                reject(h, "a.b.c", "three-sections").reason());
        assertEquals(RejectionReason.MALFORMED_TOKEN,
                reject(h, "!!!.@@@", "bad-base64").reason());
    }

    @Test
    void tamperedSignatureIsBAD_SIGNATURE() {
        GuardTestFactory.Harness h = GuardTestFactory.build();
        String token = h.tokens().issue("user").raw();
        String tampered = token.substring(0, token.length() - 2)
                + (token.endsWith("A") ? "B" : "A") + "x";
        assertEquals(RejectionReason.BAD_SIGNATURE,
                reject(h, tampered, "tampered-signature").reason());
    }

    @Test
    void tamperedPayloadIsBAD_SIGNATURE_notMalformed() {
        GuardTestFactory.Harness h = GuardTestFactory.build();
        String token = h.tokens().issue("user").raw();
        int dot = token.indexOf('.');
        // flip the first payload char but keep valid base64 alphabet/shape
        char first = token.charAt(0);
        char swap = first == 'A' ? 'B' : 'A';
        String tampered = swap + token.substring(1, dot) + token.substring(dot);
        assertEquals(RejectionReason.BAD_SIGNATURE,
                reject(h, tampered, "tampered-payload").reason());
    }

    @Test
    void expiredTokenIsEXPIRED_andDistinctFromRevoked() {
        GuardTestFactory.Harness h = GuardTestFactory.build();
        String token = h.tokens().issue("user").raw();
        h.clock().advance(Duration.ofMinutes(31));
        assertEquals(RejectionReason.EXPIRED, reject(h, token, "expired").reason());
    }

    @Test
    void revokedTokenStaysREVOKED_afterExpiry() {
        GuardTestFactory.Harness h = GuardTestFactory.build();
        String token = h.tokens().issue("user").raw();
        h.tokens().revoke(token);
        // even after expiry, explicit revocation wins (stable audit conclusion)
        h.clock().advance(Duration.ofMinutes(61));
        assertEquals(RejectionReason.REVOKED, reject(h, token, "revoked").reason());
    }

    @Test
    void wellSignedButUnknownTokenIsUNKNOWN_TOKEN() {
        GuardTestFactory.Harness h = GuardTestFactory.build();
        // Same HMAC secret but an isolated store: signature valid, jti unknown to h.
        HmacTokenSigner sameSecretSigner =
                new HmacTokenSigner("test-secret-which-is-long-enough-32b");
        TokenService isolatedTokens = new TokenService(sameSecretSigner,
                new LocalTokenStore(), Duration.ofMinutes(30), h.clock());
        String raw = isolatedTokens.issue("user").raw();
        assertEquals(RejectionReason.UNKNOWN_TOKEN,
                reject(h, raw, "foreign-store").reason());
    }

    private String abbreviate(String raw) {
        if (raw == null) {
            return "null";
        }
        return raw.length() > 24 ? raw.substring(0, 24) + "..." : raw;
    }
}
