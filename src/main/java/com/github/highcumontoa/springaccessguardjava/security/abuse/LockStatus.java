package com.github.highcumontoa.springaccessguardjava.security.abuse;

import java.time.Instant;

/**
 * 锁定查询结果。
 *
 * @param locked      当前是否处于锁定
 * @param lockedUntil 锁定到期时刻（未锁定为 null）
 * @param failures    当前窗口内累计失败次数
 */
public record LockStatus(boolean locked, Instant lockedUntil, int failures) {
}
