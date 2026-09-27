package com.github.highcumontoa.springaccessguardjava.security.token;

import java.time.Instant;

/**
 * Signs and parses compact signed tokens.
 *
 * <p>A token is {@code base64url(payloadJson).base64url(hmac)}. Parsing must
 * distinguish structural problems (MALFORMED_TOKEN) from signature mismatch
 * (BAD_SIGNATURE).
 */
public interface TokenSigner {

    /** Signed token plus the claims carried in it. */
    record Issued(String raw, String jti, String familyId, String subject,
                  Instant issuedAt, Instant expiresAt) {
    }

    Issued issue(String jti, String familyId, String subject, Instant issuedAt, Instant expiresAt);

    /** Parse result: either parseable claims or a token-specific rejection. */
    sealed interface ParseResult {
        record Ok(String jti, String familyId, String subject,
                  Instant issuedAt, Instant expiresAt) implements ParseResult {}
        record Bad(com.github.highcumontoa.springaccessguardjava.security.decision.RejectionReason reason,
                   String detail) implements ParseResult {}
    }

    ParseResult parse(String raw);
}
