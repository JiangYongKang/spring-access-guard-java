package com.github.highcumontoa.springaccessguardjava.security.abuse;

import java.time.Instant;
import java.util.Comparator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 失败计数与临时锁定：按 (账号, 来源) 维度统计。
 *
 * <p>语义：</p>
 * <ul>
 *   <li>同一 (账号, 来源) 连续失败达到阈值即进入临时锁定，锁定期间即使凭据正确也按锁定拒绝；</li>
 *   <li>锁定到期后自动恢复，恢复后重新计数；</li>
 *   <li>计数按 (账号, 来源) 隔离，异常来源不会拖垮其他用户或其他来源；</li>
 *   <li>内部记录条数有上限：满员时优先清理已恢复的过期记录，再淘汰最久未更新的记录，
 *       避免内存无限增长；</li>
 *   <li>计数与锁定状态的读写按条目串行化，高并发下不丢计数、不出现状态错乱。</li>
 * </ul>
 */
public class FailureTracker {

    private record Key(String account, String source) {
    }

    /**
     * 单个 (账号, 来源) 的失败状态。所有读写经 synchronized 串行化。
     */
    private static final class Entry {
        private int failures;
        private long lockedUntilEpochMs;
        private long lastUpdatedEpochMs;

        synchronized LockStatus onFailure(int maxFailures, long lockSeconds, long nowMs) {
            if (lockedUntilEpochMs > 0 && nowMs >= lockedUntilEpochMs) {
                // 锁定已到期：自动恢复，重新计数。
                failures = 0;
                lockedUntilEpochMs = 0;
            }
            if (lockedUntilEpochMs > 0) {
                // 锁定期间的失败不延长锁定，只更新活跃度。
                lastUpdatedEpochMs = nowMs;
                return snapshot();
            }
            failures++;
            if (failures >= maxFailures) {
                lockedUntilEpochMs = nowMs + lockSeconds * 1000;
            }
            lastUpdatedEpochMs = nowMs;
            return snapshot();
        }

        synchronized LockStatus snapshot() {
            long now = System.currentTimeMillis();
            boolean locked = lockedUntilEpochMs > 0 && now < lockedUntilEpochMs;
            Instant until = locked ? Instant.ofEpochMilli(lockedUntilEpochMs) : null;
            int effectiveFailures = (lockedUntilEpochMs > 0 && now >= lockedUntilEpochMs) ? 0 : failures;
            return new LockStatus(locked, until, effectiveFailures);
        }

        synchronized boolean isRecovered(long nowMs) {
            return lockedUntilEpochMs == 0 || nowMs >= lockedUntilEpochMs;
        }

        synchronized long lastUpdated() {
            return lastUpdatedEpochMs;
        }
    }

    private final int maxFailures;
    private final long lockSeconds;
    private final int maxEntries;
    private final Map<Key, Entry> entries = new ConcurrentHashMap<>();

    public FailureTracker(int maxFailures, long lockSeconds, int maxEntries) {
        this.maxFailures = maxFailures;
        this.lockSeconds = lockSeconds;
        this.maxEntries = maxEntries;
    }

    /**
     * 记录一次失败，返回记录后的锁定状态。
     */
    public LockStatus onFailure(String account, String source) {
        Key key = new Key(account, source);
        Entry entry = entries.get(key);
        if (entry == null) {
            ensureCapacity();
            entry = entries.computeIfAbsent(key, k -> new Entry());
        }
        return entry.onFailure(maxFailures, lockSeconds, System.currentTimeMillis());
    }

    /**
     * 成功时清除该 (账号, 来源) 的失败记录。
     */
    public void onSuccess(String account, String source) {
        entries.remove(new Key(account, source));
    }

    /**
     * 查询当前锁定状态（锁定到期视为自动恢复）。
     */
    public LockStatus status(String account, String source) {
        Entry entry = entries.get(new Key(account, source));
        return entry == null
                ? new LockStatus(false, null, 0)
                : entry.snapshot();
    }

    /**
     * 当前内部记录条数（用于验证规模上限）。
     */
    public int size() {
        return entries.size();
    }

    /**
     * 满员时先清理已恢复的过期记录，仍不足则淘汰最久未更新的记录。
     */
    private void ensureCapacity() {
        if (entries.size() < maxEntries) {
            return;
        }
        long now = System.currentTimeMillis();
        entries.entrySet().removeIf(e -> e.getValue().isRecovered(now));
        while (entries.size() >= maxEntries) {
            entries.entrySet().stream()
                    .min(Comparator.comparingLong(e -> e.getValue().lastUpdated()))
                    .ifPresent(oldest -> entries.remove(oldest.getKey(), oldest.getValue()));
            if (entries.size() >= maxEntries) {
                break; // 防御：无法淘汰时放弃跟踪新键，保证已有用户不受影响
            }
        }
    }
}
