package com.github.highcumontoa.springaccessguardjava.config;

import com.github.highcumontoa.springaccessguardjava.security.AccessGuard;
import com.github.highcumontoa.springaccessguardjava.security.auth.FailureTracker;
import com.github.highcumontoa.springaccessguardjava.security.auth.SourceRateLimiter;
import com.github.highcumontoa.springaccessguardjava.security.authorization.Authorizer;
import com.github.highcumontoa.springaccessguardjava.security.crypto.PasswordHasher;
import com.github.highcumontoa.springaccessguardjava.security.store.AccountStore;
import com.github.highcumontoa.springaccessguardjava.security.token.HmacTokenSigner;
import com.github.highcumontoa.springaccessguardjava.security.token.LocalTokenStore;
import com.github.highcumontoa.springaccessguardjava.security.token.TokenService;
import com.github.highcumontoa.springaccessguardjava.security.token.TokenSigner;
import com.github.highcumontoa.springaccessguardjava.web.GuardInterceptor;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/** Wires the local access guard: stores, crypto, services and the interceptor. */
@Configuration
@EnableConfigurationProperties(SecurityProperties.class)
public class SecurityConfig {

    @Bean
    public Clock systemClock() {
        return Clock.systemUTC();
    }

    @Bean
    public PasswordHasher passwordHasher() {
        return new PasswordHasher();
    }

    @Bean
    public AccountStore accountStore() {
        return new AccountStore();
    }

    @Bean
    public LocalTokenStore localTokenStore() {
        return new LocalTokenStore();
    }

    @Bean
    public TokenSigner tokenSigner(SecurityProperties props) {
        return new HmacTokenSigner(props.getTokenSecret());
    }

    @Bean
    public TokenService tokenService(TokenSigner signer, LocalTokenStore tokenStore,
                                     SecurityProperties props, Clock clock) {
        return new TokenService(signer, tokenStore, props.getTokenTtl(),
                props.getRefreshReuseGrace(), clock);
    }

    @Bean
    public Authorizer authorizer(AccountStore accountStore) {
        return new Authorizer(accountStore);
    }

    @Bean
    public FailureTracker failureTracker(SecurityProperties props, Clock clock) {
        return new FailureTracker(props.getLockThreshold(), props.getLockDuration(),
                props.getFailureWindow(), props.getMaxTrackedAccounts(), clock);
    }

    @Bean
    public SourceRateLimiter sourceRateLimiter(SecurityProperties props, Clock clock) {
        return new SourceRateLimiter(props.getSourceRateLimit(), props.getRateWindow(),
                props.getMaxTrackedSources(), clock);
    }

    @Bean
    public AccessGuard accessGuard(AccountStore accounts, TokenService tokens,
                                   Authorizer authorizer, PasswordHasher passwordHasher,
                                   FailureTracker failures, SourceRateLimiter rateLimiter) {
        return new AccessGuard(accounts, tokens, authorizer, passwordHasher, failures,
                rateLimiter);
    }

    @Bean
    public GuardInterceptor guardInterceptor(AccessGuard accessGuard) {
        return new GuardInterceptor(accessGuard);
    }
}
