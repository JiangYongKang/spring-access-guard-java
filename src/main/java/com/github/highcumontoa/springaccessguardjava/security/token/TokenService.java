package com.github.highcumontoa.springaccessguardjava.security.token;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 本地凭据服务：签发、校验、刷新（轮换）、吊销。
 *
 * <p>凭据传输形态为 {@code tokenId.signature}，signature 是对 tokenId 的 HMAC-SHA256。
 * 服务端保存每张凭据的状态（过期时刻、是否吊销），因此可以区分
 * 格式不合法 / 被篡改或非本服务签发 / 已过期 / 已吊销 四类失败。</p>
 *
 * <p>刷新采用“先失效旧凭据、再登记新凭据”的原子轮换：同一把锁内完成，
 * 并发刷新同一凭据时至多产生一个有效后继。</p>
 */
public class TokenService {

    /** 服务端凭据状态。 */
    private record TokenRecord(String username, Instant expiresAt, boolean revoked) {
        TokenRecord markRevoked() {
            return new TokenRecord(username, expiresAt, true);
        }
    }

    private static final int MAX_RECORDS = 100_000;

    private final byte[] secret;
    private final long ttlSeconds;
    private final Map<String, TokenRecord> records = new ConcurrentHashMap<>();
    private final Object refreshLock = new Object();

    public TokenService(String secret, long ttlSeconds) {
        this.secret = secret.getBytes(StandardCharsets.UTF_8);
        this.ttlSeconds = ttlSeconds;
    }

    /** 以默认有效期签发。 */
    public AccessToken issue(String username) {
        return issue(username, ttlSeconds);
    }

    /** 以指定有效期签发（便于测试过期场景，可传负数得到已过期凭据）。 */
    public AccessToken issue(String username, long ttl) {
        evictExpiredIfHuge();
        String tokenId = UUID.randomUUID().toString();
        Instant expiresAt = Instant.now().plusSeconds(ttl);
        records.put(tokenId, new TokenRecord(username, expiresAt, false));
        return new AccessToken(tokenId, encode(tokenId), username, expiresAt);
    }

    /**
     * 校验凭据，逐一区分失败原因。
     */
    public TokenValidation validate(String tokenValue) {
        String tokenId = parseAndVerify(tokenValue);
        if (tokenId == null) {
            return failureOf(tokenValue);
        }
        TokenRecord record = records.get(tokenId);
        if (record == null) {
            // 签名有效但查无记录（不可能发生，除非记录被清理），按篡改处理。
            return TokenValidation.of(TokenStatus.TAMPERED, null, tokenId);
        }
        if (record.revoked()) {
            return TokenValidation.of(TokenStatus.REVOKED, record.username(), tokenId);
        }
        if (Instant.now().isAfter(record.expiresAt())) {
            return TokenValidation.of(TokenStatus.EXPIRED, record.username(), tokenId);
        }
        return TokenValidation.of(TokenStatus.VALID, record.username(), tokenId);
    }

    /**
     * 刷新（轮换）：旧凭据在同一临界区内被吊销并登记后继，
     * 并发调用时至多一个成功，其余得到旧凭据的失败状态（REVOKED 等）。
     */
    public RefreshResult refresh(String tokenValue) {
        // 锁外先做廉价的格式与签名校验。
        String tokenId = parseAndVerify(tokenValue);
        if (tokenId == null) {
            return new RefreshResult(failureOf(tokenValue).status(), null);
        }
        synchronized (refreshLock) {
            TokenRecord record = records.get(tokenId);
            if (record == null) {
                return new RefreshResult(TokenStatus.TAMPERED, null);
            }
            if (record.revoked()) {
                return new RefreshResult(TokenStatus.REVOKED, null);
            }
            if (Instant.now().isAfter(record.expiresAt())) {
                return new RefreshResult(TokenStatus.EXPIRED, null);
            }
            // 原子轮换：先吊销旧凭据，再登记新凭据。
            records.put(tokenId, record.markRevoked());
            AccessToken successor = issue(record.username());
            return new RefreshResult(TokenStatus.VALID, successor);
        }
    }

    /**
     * 吊销凭据。返回是否真实吊销了一张有效凭据。
     */
    public boolean revoke(String tokenValue) {
        String tokenId = parseAndVerify(tokenValue);
        if (tokenId == null) {
            return false;
        }
        boolean[] done = {false};
        records.computeIfPresent(tokenId, (id, record) -> {
            if (!record.revoked()) {
                done[0] = true;
                return record.markRevoked();
            }
            return record;
        });
        return done[0];
    }

    // ---- 内部工具 ----

    private String encode(String tokenId) {
        return tokenId + "." + sign(tokenId);
    }

    private String sign(String tokenId) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(mac.doFinal(tokenId.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }

    /**
     * 解析并验签。返回合法且签名正确的 tokenId，否则返回 null。
     */
    private String parseAndVerify(String tokenValue) {
        if (tokenValue == null) {
            return null;
        }
        int dot = tokenValue.indexOf('.');
        if (dot <= 0 || dot == tokenValue.length() - 1 || tokenValue.indexOf('.', dot + 1) >= 0) {
            return null; // 结构不合法
        }
        String tokenId = tokenValue.substring(0, dot);
        String signature = tokenValue.substring(dot + 1);
        String expected = sign(tokenId);
        if (!MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                signature.getBytes(StandardCharsets.UTF_8))) {
            return null; // 签名不匹配
        }
        return tokenId;
    }

    /**
     * 对无法通过解析/验签的输入给出可区分结论：结构问题为 MALFORMED，其余为 TAMPERED。
     */
    private TokenValidation failureOf(String tokenValue) {
        if (tokenValue == null) {
            return TokenValidation.of(TokenStatus.MALFORMED, null, null);
        }
        int dot = tokenValue.indexOf('.');
        boolean structureOk = dot > 0 && dot < tokenValue.length() - 1
                && tokenValue.indexOf('.', dot + 1) < 0;
        if (!structureOk) {
            return TokenValidation.of(TokenStatus.MALFORMED, null, null);
        }
        String tokenId = tokenValue.substring(0, dot);
        return TokenValidation.of(TokenStatus.TAMPERED, null, tokenId);
    }

    private void evictExpiredIfHuge() {
        if (records.size() > MAX_RECORDS) {
            Instant now = Instant.now();
            records.entrySet().removeIf(e -> e.getValue().expiresAt().isBefore(now));
        }
    }
}
