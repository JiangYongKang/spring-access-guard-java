package com.github.highcumontoa.springaccessguardjava.security.model;

/**
 * Compound key of an account and a request source (client address).
 *
 * <p>Failure counts and locks are kept per {@code (account, source)} so that
 * abusive sources cannot lock a legitimate user out of other sources, and one
 * account's failures cannot poison another account.
 */
public record AccountSource(String account, String source) {

    public static AccountSource of(String account, String source) {
        return new AccountSource(account, source);
    }
}
