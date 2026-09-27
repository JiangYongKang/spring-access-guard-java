package com.github.highcumontoa.springaccessguardjava.security.token;

import com.github.highcumontoa.springaccessguardjava.security.decision.RefreshDecision;
import com.github.highcumontoa.springaccessguardjava.security.decision.RejectionReason;
import com.github.highcumontoa.springaccessguardjava.security.decision.TokenCheck;
import com.github.highcumontoa.springaccessguardjava.security.model.StoredToken;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;

/**
 * Issues, verifies, rotates and revokes access tokens.
 *
 * <p>Verification precedence (the first failing layer wins, so callers always
 * learn the true, most specific cause):
 * <ol>
 *   <li>structure/signature — MISSING/MALFORMED/BAD_SIGNATURE</li>
 *   <li>server-side state — UNKNOWN / REVOKED / REUSE_DETECTED</li>
 *   <li>expiry — EXPIRED</li>
 * </ol>
 * Revocation precedes expiry: an explicitly revoked token stays "revoked"
 * rather than drifting to "expired", which keeps audit conclusions stable.
 *
 * <p>Refresh atomically rotates a LIVE token via {@link LocalTokenStore}; under
 * concurrency exactly one caller receives the successor and losers inside a
 * short race window get REFRESH_REJECTED without any state change. Presenting a
 * rotated-away token <em>after</em> that window is token reuse/theft: the whole
 * family is revoked and the caller gets REUSE_DETECTED.
 */
public class TokenService {

    private final TokenSigner signer;
    private final LocalTokenStore store;
    private final Duration ttl;
    private final Duration reuseGrace;
    private final Clock clock;
    private final SecureRandom random = new SecureRandom();

    public TokenService(TokenSigner signer, LocalTokenStore store,
                        Duration ttl, Clock clock) {
        this(signer, store, ttl, Duration.ofSeconds(30), clock);
    }

    /**
     * @param reuseGrace after a token is rotated, presentations of the old
     *                   token within this window are treated as a concurrent
     *                   refresh race (REFRESH_REJECTED); presentations after
     *                   the window are token reuse/theft and revoke the family.
     */
    public TokenService(TokenSigner signer, LocalTokenStore store,
                        Duration ttl, Duration reuseGrace, Clock clock) {
        this.signer = signer;
        this.store = store;
        this.ttl = ttl;
        this.reuseGrace = reuseGrace;
        this.clock = clock;
    }

    public TokenSigner.Issued issue(String subject) {
        return issueInFamily(subject, newFamilyId());
    }

    /** Issue the first token of a new family (used right after authentication). */
    public TokenSigner.Issued issueInFamily(String subject, String familyId) {
        Instant now = clock.instant();
        Instant exp = now.plus(ttl);
        String jti = newId();
        TokenSigner.Issued issued = signer.issue(jti, familyId, subject, now, exp);
        store.put(new StoredToken(jti, familyId, subject, now, exp));
        return issued;
    }

    public TokenCheck verify(String raw) {
        TokenSigner.ParseResult parsed = signer.parse(raw);
        if (parsed instanceof TokenSigner.ParseResult.Bad bad) {
            return new TokenCheck.Invalid(bad.reason(), bad.detail());
        }
        TokenSigner.ParseResult.Ok claims = (TokenSigner.ParseResult.Ok) parsed;
        StoredToken stored = store.find(claims.jti()).orElse(null);
        if (stored == null) {
            return new TokenCheck.Invalid(RejectionReason.UNKNOWN_TOKEN,
                    "token jti is not recognized: " + claims.jti());
        }
        if (stored.state() == StoredToken.State.REVOKED) {
            return new TokenCheck.Invalid(RejectionReason.REVOKED,
                    "token was revoked: " + claims.jti());
        }
        if (stored.state() == StoredToken.State.ROTATED) {
            return new TokenCheck.Invalid(RejectionReason.REUSE_DETECTED,
                    "token already rotated away: " + claims.jti());
        }
        Instant now = clock.instant();
        if (!claims.expiresAt().isAfter(now)) {
            return new TokenCheck.Invalid(RejectionReason.EXPIRED,
                    "token expired at " + claims.expiresAt() + " (now " + now + ")");
        }
        return new TokenCheck.Valid(claims.jti(), claims.subject(), claims.familyId(),
                claims.issuedAt(), claims.expiresAt());
    }

    public RefreshDecision refresh(String raw) {
        TokenSigner.ParseResult parsed = signer.parse(raw);
        if (parsed instanceof TokenSigner.ParseResult.Bad bad) {
            return new RefreshDecision.Rejected(bad.reason(), bad.detail());
        }
        TokenSigner.ParseResult.Ok claims = (TokenSigner.ParseResult.Ok) parsed;
        StoredToken stored = store.find(claims.jti()).orElse(null);
        if (stored == null) {
            return new RefreshDecision.Rejected(RejectionReason.UNKNOWN_TOKEN,
                    "token jti is not recognized");
        }
        if (stored.state() == StoredToken.State.REVOKED) {
            return new RefreshDecision.Rejected(RejectionReason.REVOKED, "token was revoked");
        }
        if (stored.state() == StoredToken.State.ROTATED) {
            Instant now0 = clock.instant();
            Instant graceEndsAt = stored.rotatedAt() == null
                    ? now0 : stored.rotatedAt().plus(reuseGrace);
            if (!now0.isAfter(graceEndsAt)) {
                // Lost a concurrent refresh race moments ago; the winner's
                // successor remains the only valid credential. Do not revoke.
                return new RefreshDecision.Rejected(RejectionReason.REFRESH_REJECTED,
                        "concurrent refresh: a successor was already issued in the race window");
            }
            // After the race window, a rotated-away token being presented again
            // is token theft: revoke every token in the family.
            store.revokeFamily(stored.familyId());
            return new RefreshDecision.Rejected(RejectionReason.REUSE_DETECTED,
                    "reuse of rotated token after grace window; family "
                            + stored.familyId() + " revoked");
        }
        if (!claims.expiresAt().isAfter(clock.instant())) {
            return new RefreshDecision.Rejected(RejectionReason.EXPIRED,
                    "expired tokens cannot be refreshed; re-authenticate");
        }

        Instant now = clock.instant();
        Instant exp = now.plus(ttl);
        String successorJti = newId();
        StoredToken successor = new StoredToken(successorJti, stored.familyId(),
                stored.subject(), now, exp);
        // Atomic compare-and-rotate: losers of the race observe false here.
        if (!store.rotate(claims.jti(), successor, now)) {
            return new RefreshDecision.Rejected(RejectionReason.REFRESH_REJECTED,
                    "token was concurrently refreshed or revoked; only one successor is valid");
        }
        TokenSigner.Issued issued = signer.issue(successorJti, stored.familyId(),
                stored.subject(), now, exp);
        TokenCheck.Valid valid = new TokenCheck.Valid(successorJti, stored.subject(),
                stored.familyId(), now, exp);
        return new RefreshDecision.Rotated(issued.raw(), valid);
    }

    /** Revoke a single token when its signature is valid; malformed input is a no-op error. */
    public void revoke(String raw) {
        if (parsedJti(raw) instanceof String jti) {
            store.revoke(jti);
        }
    }

    public void revokeFamilyByRawToken(String raw) {
        if (signer.parse(raw) instanceof TokenSigner.ParseResult.Ok ok) {
            store.revokeFamily(ok.familyId());
        }
    }

    private String parsedJti(String raw) {
        return signer.parse(raw) instanceof TokenSigner.ParseResult.Ok ok ? ok.jti() : null;
    }

    private String newId() {
        byte[] bytes = new byte[24];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String newFamilyId() {
        byte[] bytes = new byte[16];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
