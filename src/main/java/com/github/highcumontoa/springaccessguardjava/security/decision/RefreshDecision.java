package com.github.highcumontoa.springaccessguardjava.security.decision;

/**
 * Result of attempting to rotate an access token.
 *
 * <p>Under concurrent refresh of the same token exactly one call can return
 * {@link Rotated}; losers observe a deterministic {@link Rejected}.
 */
public sealed interface RefreshDecision permits RefreshDecision.Rotated, RefreshDecision.Rejected {

    record Rotated(String newToken, TokenCheck.Valid claims) implements RefreshDecision {
    }

    record Rejected(RejectionReason reason, String detail) implements RefreshDecision {
    }
}
