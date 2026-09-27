package com.github.highcumontoa.springaccessguardjava;

import com.github.highcumontoa.springaccessguardjava.security.AccountStore;
import com.github.highcumontoa.springaccessguardjava.security.abuse.FailureTracker;
import com.github.highcumontoa.springaccessguardjava.security.authz.AuthorizationService;
import com.github.highcumontoa.springaccessguardjava.security.token.TokenService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * 安全组件装配。
 */
@Configuration
public class SecurityConfig {

    @Bean
    public AccountStore accountStore() {
        return new AccountStore();
    }

    @Bean
    public TokenService tokenService(
            @Value("${access-guard.token-secret}") String secret,
            @Value("${access-guard.token-ttl-seconds}") long ttlSeconds) {
        return new TokenService(secret, ttlSeconds);
    }

    @Bean
    public AuthorizationService authorizationService(TokenService tokenService, AccountStore accountStore) {
        return new AuthorizationService(tokenService, accountStore);
    }

    @Bean
    public FailureTracker failureTracker(
            @Value("${access-guard.max-failures}") int maxFailures,
            @Value("${access-guard.lock-seconds}") long lockSeconds,
            @Value("${access-guard.max-tracked-entries}") int maxEntries) {
        return new FailureTracker(maxFailures, lockSeconds, maxEntries);
    }
}
