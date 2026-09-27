package com.github.highcumontoa.springaccessguardjava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * Tunables for the local access guard. Every value can be overridden via
 * {@code access-guard.*} properties (see application.properties and README).
 */
@ConfigurationProperties(prefix = "access-guard")
public class SecurityProperties {

    /** HMAC secret used to sign tokens. Must be set in real deployments. */
    private String tokenSecret = "local-dev-secret-change-me-please-32bytes";
    /** Lifetime of an issued access token. */
    private Duration tokenTtl = Duration.ofMinutes(30);
    /**
     * After rotation, old-token presentations within this window are treated as
     * a concurrent-refresh race; after it they count as token reuse/theft.
     */
    private Duration refreshReuseGrace = Duration.ofSeconds(30);

    /** Consecutive failures (per account+source) that trigger a lock. */
    private int lockThreshold = 5;
    /** How long a lock lasts once triggered. */
    private Duration lockDuration = Duration.ofMinutes(5);
    /** Failures older than this are forgotten when counting. */
    private Duration failureWindow = Duration.ofMinutes(15);
    /** Maximum number of tracked (account, source) failure keys. */
    private int maxTrackedAccounts = 10_000;

    /** Maximum accepted requests from one source per rate-limit window. */
    private int sourceRateLimit = 60;
    /** Sliding window length for source rate limiting. */
    private Duration rateWindow = Duration.ofMinutes(1);
    /** Maximum number of tracked sources. */
    private int maxTrackedSources = 10_000;

    public String getTokenSecret() { return tokenSecret; }
    public void setTokenSecret(String tokenSecret) { this.tokenSecret = tokenSecret; }
    public Duration getTokenTtl() { return tokenTtl; }
    public void setTokenTtl(Duration tokenTtl) { this.tokenTtl = tokenTtl; }
    public Duration getRefreshReuseGrace() { return refreshReuseGrace; }
    public void setRefreshReuseGrace(Duration refreshReuseGrace) { this.refreshReuseGrace = refreshReuseGrace; }
    public int getLockThreshold() { return lockThreshold; }
    public void setLockThreshold(int lockThreshold) { this.lockThreshold = lockThreshold; }
    public Duration getLockDuration() { return lockDuration; }
    public void setLockDuration(Duration lockDuration) { this.lockDuration = lockDuration; }
    public Duration getFailureWindow() { return failureWindow; }
    public void setFailureWindow(Duration failureWindow) { this.failureWindow = failureWindow; }
    public int getMaxTrackedAccounts() { return maxTrackedAccounts; }
    public void setMaxTrackedAccounts(int maxTrackedAccounts) { this.maxTrackedAccounts = maxTrackedAccounts; }
    public int getSourceRateLimit() { return sourceRateLimit; }
    public void setSourceRateLimit(int sourceRateLimit) { this.sourceRateLimit = sourceRateLimit; }
    public Duration getRateWindow() { return rateWindow; }
    public void setRateWindow(Duration rateWindow) { this.rateWindow = rateWindow; }
    public int getMaxTrackedSources() { return maxTrackedSources; }
    public void setMaxTrackedSources(int maxTrackedSources) { this.maxTrackedSources = maxTrackedSources; }
}
