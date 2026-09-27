package com.github.highcumontoa.springaccessguardjava.security.model;

import java.time.Instant;

/**
 * Mutable server-side state of one issued access token.
 *
 * <p>State machine: {@code LIVE -> ROTATED -> REVOKED} or {@code LIVE -> REVOKED}.
 * A token marked {@code ROTATED} has exactly one successor (in the same family);
 * presenting it again is treated as credential theft and revokes the family.
 */
public final class StoredToken {

    public enum State { LIVE, ROTATED, REVOKED }

    private final String jti;
    private final String familyId;
    private final String subject;
    private final Instant issuedAt;
    private final Instant expiresAt;
    private volatile State state;
    private volatile String successorJti;
    private volatile Instant rotatedAt;

    public StoredToken(String jti, String familyId, String subject,
                       Instant issuedAt, Instant expiresAt) {
        this.jti = jti;
        this.familyId = familyId;
        this.subject = subject;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
        this.state = State.LIVE;
    }

    public String jti() { return jti; }
    public String familyId() { return familyId; }
    public String subject() { return subject; }
    public Instant issuedAt() { return issuedAt; }
    public Instant expiresAt() { return expiresAt; }
    public State state() { return state; }
    public String successorJti() { return successorJti; }
    public Instant rotatedAt() { return rotatedAt; }

    public void markRotated(String successorJti, Instant rotatedAt) {
        this.state = State.ROTATED;
        this.successorJti = successorJti;
        this.rotatedAt = rotatedAt;
    }

    public void markRevoked() {
        this.state = State.REVOKED;
    }
}
