package com.github.highcumontoa.springaccessguardjava.security.decision;

import java.time.Instant;

/**
 * Result of verifying a raw access token string.
 *
 * <p>Verification is a sealed sum type: either {@link Valid} (token is live and
 * its claims are trustworthy) or {@link Invalid} carrying one distinct
 * {@link RejectionReason}.
 */
public sealed interface TokenCheck permits TokenCheck.Valid, TokenCheck.Invalid {

    /** A live token whose signature and state have been verified. */
    record Valid(String jti,
                 String subject,
                 String familyId,
                 Instant issuedAt,
                 Instant expiresAt) implements TokenCheck {
    }

    /** A rejected token; {@code reason} is always token-specific. */
    record Invalid(RejectionReason reason, String detail) implements TokenCheck {
    }
}
