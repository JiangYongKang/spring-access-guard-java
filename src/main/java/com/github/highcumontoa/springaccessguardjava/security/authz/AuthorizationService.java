package com.github.highcumontoa.springaccessguardjava.security.authz;

import com.github.highcumontoa.springaccessguardjava.security.Account;
import com.github.highcumontoa.springaccessguardjava.security.AccountStore;
import com.github.highcumontoa.springaccessguardjava.security.Role;
import com.github.highcumontoa.springaccessguardjava.security.token.TokenService;
import com.github.highcumontoa.springaccessguardjava.security.token.TokenValidation;

import java.util.Optional;

/**
 * 授权判定：先认证（凭据校验），再按账号当前角色判定。
 *
 * <p>角色读取自账号存储的实时值，凭据本身不固化角色，
 * 因此角色调整后对同一凭据的判定语义稳定：同一请求在同一时刻只会得到一个结论，
 * 调整后的新结论对后续所有请求一致生效。</p>
 */
public class AuthorizationService {

    private final TokenService tokenService;
    private final AccountStore accountStore;

    public AuthorizationService(TokenService tokenService, AccountStore accountStore) {
        this.tokenService = tokenService;
        this.accountStore = accountStore;
    }

    public AuthorizationResult authorize(String tokenValue, Role requiredRole) {
        TokenValidation validation = tokenService.validate(tokenValue);
        if (!validation.isValid()) {
            return new AuthorizationResult(Decision.DENY_UNAUTHENTICATED, validation.status(),
                    null, "token rejected: " + validation.status());
        }
        String username = validation.username();
        Optional<Account> account = accountStore.find(username);
        if (account.isEmpty()) {
            return new AuthorizationResult(Decision.DENY_UNAUTHENTICATED, validation.status(),
                    username, "account no longer exists: " + username);
        }
        boolean granted = account.get().getRoles().stream()
                .anyMatch(role -> role.covers(requiredRole));
        if (!granted) {
            return new AuthorizationResult(Decision.DENY_FORBIDDEN, validation.status(),
                    username, "roles " + account.get().getRoles() + " do not cover " + requiredRole);
        }
        return new AuthorizationResult(Decision.ALLOW, validation.status(),
                username, "roles " + account.get().getRoles() + " cover " + requiredRole);
    }
}
