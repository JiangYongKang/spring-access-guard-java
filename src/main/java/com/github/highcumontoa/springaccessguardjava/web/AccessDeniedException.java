package com.github.highcumontoa.springaccessguardjava.web;

import com.github.highcumontoa.springaccessguardjava.security.decision.RejectionReason;

/** Carries a distinct {@link RejectionReason} up to the exception handler. */
public class AccessDeniedException extends RuntimeException {

    private final RejectionReason reason;

    public AccessDeniedException(RejectionReason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public RejectionReason reason() {
        return reason;
    }
}
