package com.github.highcumontoa.springaccessguardjava.tests;

import com.github.highcumontoa.springaccessguardjava.security.abuse.FailureTracker;
import com.github.highcumontoa.springaccessguardjava.security.abuse.LockStatus;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 失败统计与临时锁定测试：阈值锁定、到期自动恢复、并发计数不丢失、
 * 来源隔离、内部记录规模上限。
 */
class FailureTrackerTest {

    private static final Logger log = LoggerFactory.getLogger(FailureTrackerTest.class);

    @Test
    void locksAfterThresholdAndRejectsEvenValidAttempts() {
        FailureTracker tracker = new FailureTracker(3, 60, 1000);
        for (int i = 1; i <= 3; i++) {
            LockStatus status = tracker.onFailure("alice", "ip-1");
            log.info("输入=第 {} 次失败 (alice, ip-1), 判定={}", i, status);
        }
        LockStatus locked = tracker.status("alice", "ip-1");
        log.info("输入=锁定后查询（此时即使凭据正确也应按锁定拒绝）, 判定={}", locked);
        assertTrue(locked.locked());
        assertEquals(3, locked.failures());
    }

    @Test
    void lockExpiresAndRecoversAutomatically() throws Exception {
        FailureTracker tracker = new FailureTracker(2, 1, 1000); // 锁定 1 秒
        tracker.onFailure("alice", "ip-1");
        LockStatus locked = tracker.onFailure("alice", "ip-1");
        log.info("输入=达到阈值, 判定={}", locked);
        assertTrue(locked.locked());

        Thread.sleep(1100); // 等待锁定到期
        LockStatus recovered = tracker.status("alice", "ip-1");
        log.info("输入=锁定到期后查询, 判定={}", recovered);
        assertFalse(recovered.locked());
        assertEquals(0, recovered.failures());

        // 恢复后重新计数：单次失败不再锁定。
        LockStatus again = tracker.onFailure("alice", "ip-1");
        log.info("输入=恢复后第 1 次失败, 判定={}", again);
        assertFalse(again.locked());
        assertEquals(1, again.failures());
    }

    @Test
    void successClearsFailureCount() {
        FailureTracker tracker = new FailureTracker(3, 60, 1000);
        tracker.onFailure("alice", "ip-1");
        tracker.onFailure("alice", "ip-1");
        tracker.onSuccess("alice", "ip-1");
        LockStatus status = tracker.status("alice", "ip-1");
        log.info("输入=成功后查询, 判定={}", status);
        assertFalse(status.locked());
        assertEquals(0, status.failures());
    }

    @Test
    void sourcesAreIsolated() {
        FailureTracker tracker = new FailureTracker(2, 60, 1000);
        tracker.onFailure("alice", "evil-ip");
        LockStatus locked = tracker.onFailure("alice", "evil-ip");
        log.info("输入=异常来源 evil-ip 达到阈值, 判定={}", locked);
        assertTrue(locked.locked());

        // 同一账号从正常来源访问不受影响。
        LockStatus other = tracker.status("alice", "home-ip");
        log.info("输入=同一账号另一来源 home-ip, 判定={}", other);
        assertFalse(other.locked());

        // 同一来源下其他账号不受影响。
        LockStatus otherUser = tracker.status("bob", "evil-ip");
        log.info("输入=同一来源另一账号 bob, 判定={}", otherUser);
        assertFalse(otherUser.locked());
    }

    @Test
    void concurrentFailuresAreCountedWithoutLoss() throws Exception {
        FailureTracker tracker = new FailureTracker(1_000_000, 60, 1000); // 阈值足够大，只观察计数
        int threads = 8, perThread = 500;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch go = new CountDownLatch(1);
        List<Future<?>> futures = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            futures.add(pool.submit(() -> {
                ready.countDown();
                go.await();
                for (int j = 0; j < perThread; j++) {
                    tracker.onFailure("alice", "ip-1");
                }
                return null;
            }));
        }
        ready.await();
        go.countDown();
        for (Future<?> f : futures) {
            f.get();
        }
        pool.shutdown();
        LockStatus status = tracker.status("alice", "ip-1");
        log.info("输入={} 线程 x {} 次并发失败, 判定={}", threads, perThread, status);
        assertEquals(threads * perThread, status.failures(), "并发计数不能丢失");
    }

    @Test
    void trackerSizeIsBounded() {
        int maxEntries = 50;
        FailureTracker tracker = new FailureTracker(1, 60, maxEntries); // 一次失败即锁定
        // 前 maxEntries 个 (账号, 来源) 全部进入锁定。
        for (int i = 0; i < maxEntries; i++) {
            tracker.onFailure("user-" + i, "ip-" + i);
        }
        // 继续灌入大量新键，记录规模不能无限增长。
        for (int i = 0; i < 5000; i++) {
            tracker.onFailure("flood-" + i, "flood-ip-" + i);
        }
        log.info("输入=灌入 5000 个新键后, 记录条数={}", tracker.size());
        assertTrue(tracker.size() <= maxEntries, "记录规模必须有上限");
    }
}
