package com.github.highcumontoa.springaccessguardjava.security.store;

import com.github.highcumontoa.springaccessguardjava.security.model.Account;

import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * In-memory account directory.
 *
 * <p>Role updates replace the whole {@link Account} value atomically under a
 * per-account lock. Authorization always reads the current value once and takes
 * an immutable role snapshot from it, so a request can never answer against two
 * different role sets.
 */
public class AccountStore {

    private final ConcurrentMap<String, Account> accounts = new ConcurrentHashMap<>();

    public void put(Account account) {
        accounts.put(account.username(), account);
    }

    public Optional<Account> find(String username) {
        return Optional.ofNullable(accounts.get(username));
    }

    /**
     * Replace the role set atomically.
     *
     * @return false if the account does not exist.
     */
    public boolean updateRoles(String username, Set<String> roles) {
        Account existing = accounts.get(username);
        if (existing == null) {
            return false;
        }
        synchronized (existing) {
            // re-check under lock: a concurrent put may have swapped the value
            Account current = accounts.get(username);
            if (current == null) {
                return false;
            }
            accounts.put(username, new Account(current.username(), current.passwordHash(),
                    Set.copyOf(roles), current.enabled()));
            return true;
        }
    }

    public int size() {
        return accounts.size();
    }
}
