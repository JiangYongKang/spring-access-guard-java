package com.github.highcumontoa.springaccessguardjava.security.auth;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Comparator;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Bounded per-source sliding-window rate limiter.
 *
 * <p>Each source keeps the timestamps of accepted requests in the last
 * {@code window}; a request is accepted while the count is below {@code limit}.
 * It is deliberately independent from {@link FailureTracker}: a noisy source is
 * rate-limited but does not lock accounts, and a locked account does not by
 * itself block the source for everyone.
 *
 * <p>The source map is capped at {@code maxTrackedSources}; idle windows are
 * purged and, if necessary, the least-recently-used one is evicted.
 */
public class SourceRateLimiter {

    private static final class Window {
        final Deque<Instant> hits = new ArrayDeque<>();
        volatile long lastTouched;
    }

    private final int limit;
    private final Duration window;
    private final int maxTrackedSources;
    private final Clock clock;
    private final ConcurrentMap<String, Window> windows = new ConcurrentHashMap<>();

    public SourceRateLimiter(int limit, Duration window, int maxTrackedSources, Clock clock) {
        this.limit = limit;
        this.window = window;
        this.maxTrackedSources = maxTrackedSources;
        this.clock = clock;
    }

    public boolean tryAcquire(String source) {
        Instant now = clock.instant();
        Window w = obtain(source, now);
        synchronized (w) {
            Instant cutoff = now.minus(window);
            while (!w.hits.isEmpty() && !w.hits.peekFirst().isAfter(cutoff)) {
                w.hits.pollFirst();
            }
            w.lastTouched = now.toEpochMilli();
            if (w.hits.size() >= limit) {
                return false;
            }
            w.hits.addLast(now);
            return true;
        }
    }

    public int trackedSources() {
        return windows.size();
    }

    public void purge() {
        Instant now = clock.instant();
        Instant cutoff = now.minus(window);
        for (Map.Entry<String, Window> e : windows.entrySet()) {
            Window w = e.getValue();
            synchronized (w) {
                while (!w.hits.isEmpty() && !w.hits.peekFirst().isAfter(cutoff)) {
                    w.hits.pollFirst();
                }
                if (w.hits.isEmpty()) {
                    windows.remove(e.getKey(), w);
                }
            }
        }
        while (windows.size() > maxTrackedSources) {
            Map.Entry<String, Window> victim = windows.entrySet().stream()
                    .min(Comparator.comparingLong(e -> e.getValue().lastTouched))
                    .orElse(null);
            if (victim == null) {
                return;
            }
            windows.remove(victim.getKey(), victim.getValue());
        }
    }

    private Window obtain(String source, Instant now) {
        Window existing = windows.get(source);
        if (existing != null) {
            return existing;
        }
        if (windows.size() >= maxTrackedSources) {
            purge();
        }
        return windows.computeIfAbsent(source, k -> new Window());
    }
}
