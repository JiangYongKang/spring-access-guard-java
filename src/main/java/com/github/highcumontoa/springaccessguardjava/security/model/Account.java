package com.github.highcumontoa.springaccessguardjava.security.model;

import java.util.Set;

/**
 * A local user account.
 *
 * <p>Roles are <b>live</b>: an access token only carries the account identity;
 * role membership is read from the account store on every request. Adjusting
 * roles therefore takes effect immediately for all already-issued tokens, and a
 * single request is always evaluated against one immutable role snapshot.
 */
public record Account(String username, String passwordHash, Set<String> roles, boolean enabled) {

    public Account {
        roles = Set.copyOf(roles);
    }

    public boolean hasRole(String role) {
        return roles.contains(role);
    }
}
