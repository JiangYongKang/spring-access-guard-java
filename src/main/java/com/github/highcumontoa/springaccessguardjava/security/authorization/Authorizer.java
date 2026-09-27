package com.github.highcumontoa.springaccessguardjava.security.authorization;

import com.github.highcumontoa.springaccessguardjava.security.decision.AccessDecision;
import com.github.highcumontoa.springaccessguardjava.security.decision.RejectionReason;
import com.github.highcumontoa.springaccessguardjava.security.decision.TokenCheck;
import com.github.highcumontoa.springaccessguardjava.security.model.Account;
import com.github.highcumontoa.springaccessguardjava.security.store.AccountStore;

import java.util.Set;

/**
 * Role based authorization over an already-verified token.
 *
 * <p>Role semantics (documented in README):
 * <ul>
 *   <li>The token proves identity only; roles are read <b>live</b> from
 *       {@link AccountStore} on each request. Role changes take effect for all
 *       already-issued tokens immediately.</li>
 *   <li>The account record and its role set are immutable snapshots, read once
 *       per request, so a request's conclusion cannot flip mid-processing.</li>
 *   <li>A missing/disabled account and a missing role both map to FORBIDDEN
 *       only when a valid identity was established; callers without a valid
 *       token never reach this class and stay unauthenticated.</li>
 * </ul>
 */
public class Authorizer {

    private final AccountStore accounts;

    public Authorizer(AccountStore accounts) {
        this.accounts = accounts;
    }

    public AccessDecision decide(TokenCheck.Valid token, String requiredRole) {
        Account account = accounts.find(token.subject()).orElse(null);
        if (account == null || !account.enabled()) {
            return new AccessDecision.Denied(RejectionReason.FORBIDDEN,
                    "authenticated identity '" + token.subject()
                            + "' is not an active account");
        }
        Set<String> roles = account.roles(); // immutable snapshot
        if (requiredRole != null && !requiredRole.isBlank()
                && !account.hasRole(requiredRole)) {
            return new AccessDecision.Denied(RejectionReason.FORBIDDEN,
                    "identity '" + token.subject() + "' with roles " + roles
                            + " lacks required role '" + requiredRole + "'");
        }
        return new AccessDecision.Allowed(account.username(), roles);
    }

    public AccessDecision deny(RejectionReason reason, String detail) {
        return new AccessDecision.Denied(reason, detail);
    }
}
