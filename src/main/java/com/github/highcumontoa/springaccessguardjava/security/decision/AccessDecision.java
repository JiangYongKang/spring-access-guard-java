package com.github.highcumontoa.springaccessguardjava.security.decision;

import java.util.Set;

/**
 * Result of authorizing a single protected request.
 *
 * <p>{@code Allowed} means the caller was authenticated <em>and</em> held the
 * required role. {@code Denied} distinguishes authentication failures (no
 * trustworthy identity established) from authorization failures (an identity
 * was established but lacked the role).
 */
public sealed interface AccessDecision permits AccessDecision.Allowed, AccessDecision.Denied {

    record Allowed(String subject, Set<String> roles) implements AccessDecision {
    }

    record Denied(RejectionReason reason, String detail) implements AccessDecision {

        /** @return true when an identity was established but lacked the role. */
        public boolean authenticatedButForbidden() {
            return reason == RejectionReason.FORBIDDEN;
        }
    }
}
