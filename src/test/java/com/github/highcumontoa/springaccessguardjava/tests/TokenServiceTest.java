package com.github.highcumontoa.springaccessguardjava.tests;

import com.github.highcumontoa.springaccessguardjava.security.token.AccessToken;
import com.github.highcumontoa.springaccessguardjava.security.token.RefreshResult;
import com.github.highcumontoa.springaccessguardjava.security.token.TokenService;
import com.github.highcumontoa.springaccessguardjava.security.token.TokenStatus;
import com.github.highcumontoa.springaccessguardjava.security.token.TokenValidation;
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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 凭据服务测试：区分过期 / 吊销 / 篡改 / 格式不合法，验证并发刷新只产生一个后继。
 */
class TokenServiceTest {

    private static final Logger log = LoggerFactory.getLogger(TokenServiceTest.class);

    private final TokenService tokenService = new TokenService("test-secret", 3600);

    @Test
    void validTokenPasses() {
        AccessToken token = tokenService.issue("alice");
        TokenValidation result = tokenService.validate(token.value());
        log.info("输入=有效凭据 [{}], 判定={}", token.value(), result);
        assertEquals(TokenStatus.VALID, result.status());
        assertEquals("alice", result.username());
    }

    @Test
    void malformedInputsAreDistinguished() {
        for (String bad : new String[]{null, "", "no-dot", ".sig", "id.", "a.b.c"}) {
            TokenValidation result = tokenService.validate(bad);
            log.info("输入=[{}], 判定={}", bad, result);
            assertEquals(TokenStatus.MALFORMED, result.status(), "input=" + bad);
        }
    }

    @Test
    void tamperedSignatureIsDistinguished() {
        AccessToken token = tokenService.issue("alice");
        String tampered = token.tokenId() + ".AAAA" + token.value().split("\\.")[1].substring(4);
        TokenValidation result = tokenService.validate(tampered);
        log.info("输入=篡改签名 [{}], 判定={}", tampered, result);
        assertEquals(TokenStatus.TAMPERED, result.status());

        // 未知 id 但结构合法：签名必然不匹配，同样按篡改处理。
        TokenValidation unknown = tokenService.validate("00000000-0000-0000-0000-000000000000.XXXX");
        log.info("输入=未知凭据, 判定={}", unknown);
        assertEquals(TokenStatus.TAMPERED, unknown.status());
    }

    @Test
    void expiredTokenIsDistinguished() {
        AccessToken token = tokenService.issue("alice", -1); // 已过期
        TokenValidation result = tokenService.validate(token.value());
        log.info("输入=过期凭据, 判定={}", result);
        assertEquals(TokenStatus.EXPIRED, result.status());
    }

    @Test
    void revokedTokenIsDistinguished() {
        AccessToken token = tokenService.issue("alice");
        assertTrue(tokenService.revoke(token.value()));
        TokenValidation result = tokenService.validate(token.value());
        log.info("输入=已吊销凭据, 判定={}", result);
        assertEquals(TokenStatus.REVOKED, result.status());
        // 重复吊销返回 false，状态不错乱。
        assertFalse(tokenService.revoke(token.value()));
    }

    @Test
    void refreshRotatesAndInvalidatesOldToken() {
        AccessToken old = tokenService.issue("alice");
        RefreshResult result = tokenService.refresh(old.value());
        log.info("输入=刷新旧凭据, 判定={}, 新凭据={}", result.status(), result.token());
        assertTrue(result.isSuccess());
        assertNotEquals(old.tokenId(), result.token().tokenId());
        assertEquals(TokenStatus.REVOKED, tokenService.validate(old.value()).status());
        assertEquals(TokenStatus.VALID, tokenService.validate(result.token().value()).status());
    }

    @Test
    void refreshRejectsExpiredAndRevokedWithDistinctReasons() {
        AccessToken expired = tokenService.issue("alice", -1);
        RefreshResult expiredResult = tokenService.refresh(expired.value());
        log.info("输入=刷新过期凭据, 判定={}", expiredResult.status());
        assertEquals(TokenStatus.EXPIRED, expiredResult.status());

        AccessToken revoked = tokenService.issue("alice");
        tokenService.revoke(revoked.value());
        RefreshResult revokedResult = tokenService.refresh(revoked.value());
        log.info("输入=刷新已吊销凭据, 判定={}", revokedResult.status());
        assertEquals(TokenStatus.REVOKED, revokedResult.status());
    }

    @Test
    void concurrentRefreshProducesExactlyOneSuccessor() throws Exception {
        AccessToken token = tokenService.issue("alice");
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch go = new CountDownLatch(1);
        List<Future<RefreshResult>> futures = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            futures.add(pool.submit(() -> {
                ready.countDown();
                go.await();
                return tokenService.refresh(token.value());
            }));
        }
        ready.await();
        go.countDown();

        List<RefreshResult> successes = new ArrayList<>();
        List<RefreshResult> failures = new ArrayList<>();
        for (Future<RefreshResult> f : futures) {
            RefreshResult r = f.get();
            (r.isSuccess() ? successes : failures).add(r);
        }
        pool.shutdown();
        log.info("输入={} 路并发刷新同一凭据, 成功数={}, 失败数={}", threads, successes.size(), failures.size());
        successes.forEach(r -> log.info("成功后继: {}", r.token().tokenId()));
        failures.forEach(r -> log.info("失败原因: {}", r.status()));

        assertEquals(1, successes.size(), "并发刷新至多一个成功");
        assertEquals(threads - 1, failures.size());
        // 失败者必须得到可区分原因（旧凭据已被轮换吊销）。
        failures.forEach(r -> assertEquals(TokenStatus.REVOKED, r.status()));
        // 旧凭据失效，唯一后继有效。
        assertEquals(TokenStatus.REVOKED, tokenService.validate(token.value()).status());
        assertEquals(TokenStatus.VALID, tokenService.validate(successes.get(0).token().value()).status());
    }
}
