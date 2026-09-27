package com.github.highcumontoa.springaccessguardjava.security.auth;

import com.github.highcumontoa.springaccessguardjava.security.model.AccountSource;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Comparator;
import java.util.Deque;
import java.util.Iterator;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Bounded per {@code (account, source)} failure counter and temporary lock.
 *
 * <p>Semantics:
 * <ul>
 *   <li>Failures inside a sliding {@code failureWindow} count consecutively;
 *       a successful authentication clears the key.</li>
 *   <li>When the count reaches {@code lockThreshold} the key is locked until
 *       {@code now + lockDuration}. While locked, even correct credentials are
 *       refused with {@code ACCOUNT_LOCKED}.</li>
 *   <li>A lock expires by wall-clock time: once the instant passes, the next
 *       request is accepted and counters restart — no background job needed.</li>
 *   <li>Keys are independent, so an abusive source cannot lock a user on other
 *       sources and one account cannot poison another.</li>
 *   <li>The map is capped at {@code maxTracked}: when full, expired/empty
 *       entries are purged first; if still full the least-recently-touched
 *       entry is evicted. A live-locked key is never evicted (its lock must
 *       keep having effect).</li>
 * </ul>
 * All state per key is mutated under that key's own monitor, so counts cannot
 * be lost under concurrency.
 */
public class FailureTracker {

    private static final class KeyState {
        final Deque<Instant> failures = new ArrayDeque<>();
        volatile Instant lockedUntil;
        volatile long lastTouched;

        void touch(Instant now) {
            lastTouched = now.toEpochMilli();
        }
    }

    private final int lockThreshold;
    private final Duration lockDuration;
    private final Duration failureWindow;
    private final int maxTracked;
    private final Clock clock;
    private final ConcurrentMap<AccountSource, KeyState> keys = new ConcurrentHashMap<>();

    public FailureTracker(int lockThreshold, Duration lockDuration,
                          Duration failureWindow, int maxTracked, Clock clock) {
        this.lockThreshold = lockThreshold;
        this.lockDuration = lockDuration;
        this.failureWindow = failureWindow;
        this.maxTracked = maxTracked;
        this.clock = clock;
    }

    public void recordFailure(AccountSource key) {
        Instant now = clock.instant();
        KeyState state = obtain(key, now);
        synchronized (state) {
            expireLockIfDue(state, now);
            pruneFailures(state, now);
            state.failures.addLast(now);
            state.touch(now);
            if (state.failures.size() >= lockThreshold) {
                state.lockedUntil = now.plus(lockDuration);
            }
        }
    }

    public void recordSuccess(AccountSource key) {
        Instant now = clock.instant();
        KeyState state = keys.get(key);
        if (state == null) {
            return;
        }
        synchronized (state) {
            state.failures.clear();
            state.lockedUntil = null;
            state.touch(now);
        }
    }

    public Optional<Instant> lockedUntil(AccountSource key) {
        Instant now = clock.instant();
        KeyState state = keys.get(key);
        if (state == null) {
            return Optional.empty();
        }
        synchronized (state) {
            expireLockIfDue(state, now);
            pruneFailures(state, now);
            return Optional.ofNullable(state.lockedUntil);
        }
    }

    public int failureCount(AccountSource key) {
        Instant now = clock.instant();
        KeyState state = keys.get(key);
        if (state == null) {
            return 0;
        }
        synchronized (state) {
            pruneFailures(state, now);
            return state.failures.size();
        }
    }

    public int trackedKeys() {
        return keys.size();
    }

    /** Drop expired/empty state and enforce the size cap. */
    public void purge() {
        Instant now = clock.instant();
        for (Map.Entry<AccountSource, KeyState> e : keys.entrySet()) {
            KeyState state = e.getValue();
            synchronized (state) {
                expireLockIfDue(state, now);
                pruneFailures(state, now);
                if (state.failures.isEmpty() && state.lockedUntil == null) {
                    keys.remove(e.getKey(), state);
                }
            }
        }
        enforceCapacity(now);
    }

    private KeyState obtain(AccountSource key, Instant now) {
        KeyState existing = keys.get(key);
        if (existing != null) {
            existing.touch(now);
            return existing;
        }
        if (keys.size() >= maxTracked) {
            purge();
        }
        // computeIfAbsent runs under the segment lock; the capacity check above
        // makes the growth bounded (slight overshoot under a race is acceptable,
        // a subsequent purge restores the cap).
        return keys.computeIfAbsent(key, k -> {
            KeyState s = new KeyState();
            s.touch(now);
            return s;
        });
    }

    private void expireLockIfDue(KeyState state, Instant now) {
        Instant until = state.lockedUntil;
        if (until != null && !until.isAfter(now)) {
            // lock period is over: old failures no longer count
            state.lockedUntil = null;
            state.failures.clear();
        }
    }

    private void pruneFailures(KeyState state, Instant now) {
        Instant cutoff = now.minus(failureWindow);
        Iterator<Instant> it = state.failures.iterator();
        while (it.hasNext()) {
            if (it.next().isBefore(cutoff)) {
                it.remove();
            } else {
                break; // deque is chronologically ordered
            }
        }
    }

    /** If still over cap after purging, evict the oldest idle, non-locked key. */
    private void enforceCapacity(Instant now) {
        while (keys.size() > maxTracked) {
            Map.Entry<AccountSource, KeyState> victim = keys.entrySet().stream()
                    .filter(e -> e.getValue().lockedUntil == null)
                    .min(Comparator.comparingLong(e -> e.getValue().lastTouched))
                    .orElse(null);
            if (victim == null) {
                return; // everything is locked; let it age out rather than weaken a lock
            }
            keys.remove(victim.getKey(), victim.getValue());
        }
    }
}
