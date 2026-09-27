package com.github.highcumontoa.springaccessguardjava.security.decision;

/**
 * Result of a local username/password authentication attempt.
 */
public sealed interface LoginDecision permits LoginDecision.Success, LoginDecision.Failure {

    record Success(String token, TokenCheck.Valid claims) implements LoginDecision {
    }

    record Failure(RejectionReason reason, String detail) implements LoginDecision {
    }
}
