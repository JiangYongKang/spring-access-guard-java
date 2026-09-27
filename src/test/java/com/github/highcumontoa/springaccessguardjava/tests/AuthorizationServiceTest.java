package com.github.highcumontoa.springaccessguardjava.tests;

import com.github.highcumontoa.springaccessguardjava.security.AccountStore;
import com.github.highcumontoa.springaccessguardjava.security.Role;
import com.github.highcumontoa.springaccessguardjava.security.authz.AuthorizationResult;
import com.github.highcumontoa.springaccessguardjava.security.authz.AuthorizationService;
import com.github.highcumontoa.springaccessguardjava.security.authz.Decision;
import com.github.highcumontoa.springaccessguardjava.security.token.AccessToken;
import com.github.highcumontoa.springaccessguardjava.security.token.TokenService;
import com.github.highcumontoa.springaccessguardjava.security.token.TokenStatus;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 授权判定测试：未认证与越权可区分，角色调整后判定语义稳定。
 */
class AuthorizationServiceTest {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationServiceTest.class);

    private final TokenService tokenService = new TokenService("test-secret", 3600);
    private final AccountStore accountStore = new AccountStore();
    private final AuthorizationService authz = new AuthorizationService(tokenService, accountStore);

    @Test
    void unauthenticatedAndForbiddenAreDistinguished() {
        AuthorizationResult noToken = authz.authorize(null, Role.USER);
        log.info("输入=无凭据访问 USER 资源, 判定={}", noToken);
        assertEquals(Decision.DENY_UNAUTHENTICATED, noToken.decision());
        assertEquals(TokenStatus.MALFORMED, noToken.tokenStatus());

        AccessToken aliceToken = tokenService.issue("alice");
        AuthorizationResult forbidden = authz.authorize(aliceToken.value(), Role.ADMIN);
        log.info("输入=alice(USER) 访问 ADMIN 资源, 判定={}", forbidden);
        assertEquals(Decision.DENY_FORBIDDEN, forbidden.decision());
        assertEquals(TokenStatus.VALID, forbidden.tokenStatus());

        AuthorizationResult allowed = authz.authorize(aliceToken.value(), Role.USER);
        log.info("输入=alice(USER) 访问 USER 资源, 判定={}", allowed);
        assertEquals(Decision.ALLOW, allowed.decision());
    }

    @Test
    void adminCoversUserRole() {
        AccessToken adminToken = tokenService.issue("admin");
        AuthorizationResult result = authz.authorize(adminToken.value(), Role.USER);
        log.info("输入=admin 访问 USER 资源, 判定={}", result);
        assertEquals(Decision.ALLOW, result.decision());
    }

    @Test
    void invalidTokenDenialCarriesDistinctTokenStatus() {
        AccessToken expired = tokenService.issue("alice", -1);
        AuthorizationResult result = authz.authorize(expired.value(), Role.USER);
        log.info("输入=过期凭据访问 USER 资源, 判定={}", result);
        assertEquals(Decision.DENY_UNAUTHENTICATED, result.decision());
        assertEquals(TokenStatus.EXPIRED, result.tokenStatus());
    }

    @Test
    void roleChangeTakesEffectImmediatelyAndConsistently() {
        accountStore.register("bob", "bob-pass", Set.of(Role.USER));
        AccessToken bobToken = tokenService.issue("bob");

        AuthorizationResult before = authz.authorize(bobToken.value(), Role.ADMIN);
        log.info("输入=bob(USER) 访问 ADMIN 资源（提权前）, 判定={}", before);
        assertEquals(Decision.DENY_FORBIDDEN, before.decision());

        // 提升为 ADMIN 后，同一凭据的后续判定一致放行。
        accountStore.updateRoles("bob", Set.of(Role.ADMIN, Role.USER));
        AuthorizationResult after1 = authz.authorize(bobToken.value(), Role.ADMIN);
        AuthorizationResult after2 = authz.authorize(bobToken.value(), Role.ADMIN);
        log.info("输入=bob(ADMIN) 访问 ADMIN 资源（提权后）, 判定1={}, 判定2={}", after1, after2);
        assertEquals(Decision.ALLOW, after1.decision());
        assertEquals(Decision.ALLOW, after2.decision());

        // 再降回 USER，同一凭据立即恢复拒绝，且结论稳定。
        accountStore.updateRoles("bob", Set.of(Role.USER));
        AuthorizationResult demoted = authz.authorize(bobToken.value(), Role.ADMIN);
        log.info("输入=bob(USER) 访问 ADMIN 资源（降权后）, 判定={}", demoted);
        assertEquals(Decision.DENY_FORBIDDEN, demoted.decision());
    }

    @Test
    void repeatedSameRequestYieldsSameDecision() {
        AccessToken token = tokenService.issue("alice");
        AuthorizationResult first = authz.authorize(token.value(), Role.ADMIN);
        AuthorizationResult second = authz.authorize(token.value(), Role.ADMIN);
        log.info("输入=同一请求重复判定, 判定1={}, 判定2={}", first, second);
        assertEquals(first.decision(), second.decision());
        assertTrue(first.detail().equals(second.detail()));
    }
}
