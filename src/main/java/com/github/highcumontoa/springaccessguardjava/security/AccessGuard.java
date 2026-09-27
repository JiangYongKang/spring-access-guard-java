package com.github.highcumontoa.springaccessguardjava.security;

import com.github.highcumontoa.springaccessguardjava.security.auth.FailureTracker;
import com.github.highcumontoa.springaccessguardjava.security.auth.SourceRateLimiter;
import com.github.highcumontoa.springaccessguardjava.security.authorization.Authorizer;
import com.github.highcumontoa.springaccessguardjava.security.crypto.PasswordHasher;
import com.github.highcumontoa.springaccessguardjava.security.decision.AccessDecision;
import com.github.highcumontoa.springaccessguardjava.security.decision.LoginDecision;
import com.github.highcumontoa.springaccessguardjava.security.decision.RefreshDecision;
import com.github.highcumontoa.springaccessguardjava.security.decision.RejectionReason;
import com.github.highcumontoa.springaccessguardjava.security.decision.TokenCheck;
import com.github.highcumontoa.springaccessguardjava.security.model.Account;
import com.github.highcumontoa.springaccessguardjava.security.model.AccountSource;
import com.github.highcumontoa.springaccessguardjava.security.store.AccountStore;
import com.github.highcumontoa.springaccessguardjava.security.token.TokenService;
import com.github.highcumontoa.springaccessguardjava.security.token.TokenSigner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.Optional;

/**
 * Single facade used by every entry point (login, refresh, protected APIs and
 * the interceptor), so conclusions and their precedence are identical
 * everywhere:
 * <ol>
 *   <li>source rate limit (RATE_LIMITED) — independent of account state</li>
 *   <li>account/source lock (ACCOUNT_LOCKED) — even correct credentials lose</li>
 *   <li>credential verification (token or password)</li>
 *   <li>role authorization (FORBIDDEN vs. an unauthenticated rejection)</li>
 * </ol>
 */
public class AccessGuard {

    private static final Logger log = LoggerFactory.getLogger(AccessGuard.class);

    private final AccountStore accounts;
    private final TokenService tokens;
    private final Authorizer authorizer;
    private final PasswordHasher passwordHasher;
    private final FailureTracker failures;
    private final SourceRateLimiter rateLimiter;

    public AccessGuard(AccountStore accounts, TokenService tokens, Authorizer authorizer,
                       PasswordHasher passwordHasher, FailureTracker failures,
                       SourceRateLimiter rateLimiter) {
        this.accounts = accounts;
        this.tokens = tokens;
        this.authorizer = authorizer;
        this.passwordHasher = passwordHasher;
        this.failures = failures;
        this.rateLimiter = rateLimiter;
    }

    public LoginDecision login(String username, String password, String source) {
        log.info("login input: username='{}', source='{}'", username, source);
        if (!rateLimiter.tryAcquire(source)) {
            log.info("login decision: RATE_LIMITED for source='{}'", source);
            return new LoginDecision.Failure(RejectionReason.RATE_LIMITED,
                    "source '" + source + "' exceeded request rate");
        }
        AccountSource key = AccountSource.of(username, source);
        Optional<Instant> locked = failures.lockedUntil(key);
        if (locked.isPresent()) {
            log.info("login decision: ACCOUNT_LOCKED username='{}' source='{}' until={}",
                    username, source, locked.get());
            return new LoginDecision.Failure(RejectionReason.ACCOUNT_LOCKED,
                    "credentials for '" + username + "' from '" + source
                            + "' are locked until " + locked.get());
        }

        Account account = accounts.find(username).orElse(null);
        boolean passwordOk = account != null
                && account.enabled()
                && passwordHasher.matches(password, account.passwordHash());
        if (!passwordOk) {
            failures.recordFailure(key);
            log.info("login decision: BAD_CREDENTIALS username='{}' source='{}' failures={}",
                    username, source, failures.failureCount(key));
            return new LoginDecision.Failure(RejectionReason.BAD_CREDENTIALS,
                    "unknown account, disabled account, or wrong password");
        }

        failures.recordSuccess(key);
        TokenSigner.Issued issued = tokens.issue(username);
        TokenCheck.Valid claims = new TokenCheck.Valid(issued.jti(), issued.subject(),
                issued.familyId(), issued.issuedAt(), issued.expiresAt());
        log.info("login decision: SUCCESS username='{}' jti='{}' expiresAt={}",
                username, claims.jti(), claims.expiresAt());
        return new LoginDecision.Success(issued.raw(), claims);
    }

    public AccessDecision authorize(String rawToken, String requiredRole, String source) {
        log.info("authorize input: requiredRole='{}', source='{}', tokenPresent={}",
                requiredRole, source, rawToken != null && !rawToken.isBlank());
        if (!rateLimiter.tryAcquire(source)) {
            log.info("authorize decision: RATE_LIMITED source='{}'", source);
            return new AccessDecision.Denied(RejectionReason.RATE_LIMITED,
                    "source '" + source + "' exceeded request rate");
        }
        TokenCheck check = tokens.verify(rawToken);
        if (check instanceof TokenCheck.Invalid invalid) {
            log.info("authorize decision: token rejected reason={} detail='{}'",
                    invalid.reason(), invalid.detail());
            return new AccessDecision.Denied(invalid.reason(), invalid.detail());
        }
        TokenCheck.Valid valid = (TokenCheck.Valid) check;

        // A locked (account, source) pair loses even with a perfectly valid token.
        AccountSource key = AccountSource.of(valid.subject(), source);
        Optional<Instant> locked = failures.lockedUntil(key);
        if (locked.isPresent()) {
            log.info("authorize decision: ACCOUNT_LOCKED subject='{}' source='{}' until={}",
                    valid.subject(), source, locked.get());
            return new AccessDecision.Denied(RejectionReason.ACCOUNT_LOCKED,
                    "account '" + valid.subject() + "' is locked from '" + source
                            + "' until " + locked.get());
        }

        AccessDecision decision = authorizer.decide(valid, requiredRole);
        if (decision instanceof AccessDecision.Allowed allowed) {
            log.info("authorize decision: ALLOWED subject='{}' roles={} requiredRole='{}'",
                    allowed.subject(), allowed.roles(), requiredRole);
        } else {
            AccessDecision.Denied denied = (AccessDecision.Denied) decision;
            log.info("authorize decision: {} detail='{}'", denied.reason(), denied.detail());
        }
        return decision;
    }

    public RefreshDecision refresh(String rawToken, String source) {
        log.info("refresh input: source='{}', tokenPresent={}",
                source, rawToken != null && !rawToken.isBlank());
        if (!rateLimiter.tryAcquire(source)) {
            log.info("refresh decision: RATE_LIMITED source='{}'", source);
            return new RefreshDecision.Rejected(RejectionReason.RATE_LIMITED,
                    "source '" + source + "' exceeded request rate");
        }
        RefreshDecision decision = tokens.refresh(rawToken);
        if (decision instanceof RefreshDecision.Rotated rotated) {
            log.info("refresh decision: ROTATED subject='{}' newJti='{}' expiresAt={}",
                    rotated.claims().subject(), rotated.claims().jti(),
                    rotated.claims().expiresAt());
        } else {
            RefreshDecision.Rejected rejected = (RefreshDecision.Rejected) decision;
            log.info("refresh decision: {} detail='{}'", rejected.reason(), rejected.detail());
        }
        return decision;
    }

    public void logout(String rawToken) {
        log.info("logout input: tokenPresent={}", rawToken != null && !rawToken.isBlank());
        tokens.revoke(rawToken);
        log.info("logout decision: token revoked (when recognizable)");
    }
}
