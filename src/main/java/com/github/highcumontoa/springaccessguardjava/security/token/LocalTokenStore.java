package com.github.highcumontoa.springaccessguardjava.security.token;

import com.github.highcumontoa.springaccessguardjava.security.model.StoredToken;

import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

/**
 * In-memory index of token server-side state.
 *
 * <p>All state transitions take one lock so that a concurrent refresh of the
 * same token is serialized: the first call marks the old token
 * {@code ROTATED} and inserts the successor, later callers see the non-LIVE
 * state and fail. Consequently each token has at most one valid successor and
 * two concurrent refreshes can never yield two live successors.
 */
public class LocalTokenStore {

    private final Map<String, StoredToken> byJti = new ConcurrentHashMap<>();
    private final Map<String, Set<String>> familyIndex = new ConcurrentHashMap<>();
    private final ReentrantLock transitionLock = new ReentrantLock();

    public void put(StoredToken token) {
        transitionLock.lock();
        try {
            byJti.put(token.jti(), token);
            familyIndex.computeIfAbsent(token.familyId(), k -> ConcurrentHashMap.newKeySet())
                    .add(token.jti());
        } finally {
            transitionLock.unlock();
        }
    }

    public Optional<StoredToken> find(String jti) {
        return Optional.ofNullable(byJti.get(jti));
    }

    /**
     * Atomically mark {@code jti} ROTATED and insert its successor.
     *
     * @return false if the token is unknown or no longer LIVE (a concurrent
     *         refresh won, it was revoked, etc.); no state changed.
     */
    public boolean rotate(String jti, StoredToken successor, java.time.Instant now) {
        transitionLock.lock();
        try {
            StoredToken current = byJti.get(jti);
            if (current == null || current.state() != StoredToken.State.LIVE) {
                return false;
            }
            byJti.put(successor.jti(), successor);
            familyIndex.computeIfAbsent(successor.familyId(), k -> ConcurrentHashMap.newKeySet())
                    .add(successor.jti());
            current.markRotated(successor.jti(), now);
            return true;
        } finally {
            transitionLock.unlock();
        }
    }

    public void revoke(String jti) {
        transitionLock.lock();
        try {
            StoredToken token = byJti.get(jti);
            if (token != null) {
                token.markRevoked();
            }
        } finally {
            transitionLock.unlock();
        }
    }

    /** Revoke every token in a family (used when a rotated-away token is reused). */
    public void revokeFamily(String familyId) {
        transitionLock.lock();
        try {
            Set<String> members = familyIndex.get(familyId);
            if (members == null) {
                return;
            }
            for (String memberJti : new HashSet<>(members)) {
                StoredToken token = byJti.get(memberJti);
                if (token != null) {
                    token.markRevoked();
                }
            }
        } finally {
            transitionLock.unlock();
        }
    }

    public int size() {
        return byJti.size();
    }
}
