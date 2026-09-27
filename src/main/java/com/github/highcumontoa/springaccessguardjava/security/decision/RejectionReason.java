package com.github.highcumontoa.springaccessguardjava.security.decision;

/**
 * All rejection reasons produced by the local access guard.
 *
 * <p>Every distinct failure mode has its own constant so callers never have to
 * collapse unrelated failures (for example expiry vs. tampering) into one
 * generic "authentication failed". The HTTP status mapping lives in
 * {@code ApiExceptionHandler}.
 */
public enum RejectionReason {

    /** No Authorization header / token presented. */
    MISSING_TOKEN(false),
    /** Token is not in the signed {@code base64.base64.base64} shape. */
    MALFORMED_TOKEN(false),
    /** Token structure is valid but its signature does not match. */
    BAD_SIGNATURE(false),
    /** Token was valid but has been explicitly revoked. */
    REVOKED(false),
    /** Token has passed its expiration instant. */
    EXPIRED(false),
    /** Token claims do not refer to a known account/credential. */
    UNKNOWN_TOKEN(false),
    /** A refreshed-away token was presented again: the whole family is revoked. */
    REUSE_DETECTED(false),
    /** Refresh failed for any reason; no successor credential was issued. */
    REFRESH_REJECTED(false),

    /** Login with an unknown account or wrong password. */
    BAD_CREDENTIALS(false),

    /** The (account, source) key is temporarily locked after repeated failures. */
    ACCOUNT_LOCKED(true),
    /** The source is above its request rate limit. */
    RATE_LIMITED(true),

    /** The caller is authenticated but lacks the required role. */
    FORBIDDEN(false);

    private final boolean abuseControl;

    RejectionReason(boolean abuseControl) {
        this.abuseControl = abuseControl;
    }

    /**
     * @return {@code true} when this reason comes from the failure/rate-limit
     *         subsystem rather than from credential or role evaluation.
     */
    public boolean isAbuseControl() {
        return abuseControl;
    }
}
