package com.github.highcumontoa.springaccessguardjava.security.token;

import java.time.Instant;

/**
 * 已签发的访问凭据。
 *
 * @param tokenId   凭据标识
 * @param value     传输形态的凭据字符串（id.signature）
 * @param username  所属账号
 * @param expiresAt 过期时刻
 */
public record AccessToken(String tokenId, String value, String username, Instant expiresAt) {
}
