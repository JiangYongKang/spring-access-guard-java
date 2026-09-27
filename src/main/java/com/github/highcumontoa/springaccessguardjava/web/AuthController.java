package com.github.highcumontoa.springaccessguardjava.web;

import com.github.highcumontoa.springaccessguardjava.security.AccountStore;
import com.github.highcumontoa.springaccessguardjava.security.abuse.FailureTracker;
import com.github.highcumontoa.springaccessguardjava.security.abuse.LockStatus;
import com.github.highcumontoa.springaccessguardjava.security.token.AccessToken;
import com.github.highcumontoa.springaccessguardjava.security.token.RefreshResult;
import com.github.highcumontoa.springaccessguardjava.security.token.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 认证入口：登录签发、刷新、吊销。
 * 登录按 (账号, 来源) 做失败统计与临时锁定。
 */
@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AccountStore accountStore;
    private final TokenService tokenService;
    private final FailureTracker failureTracker;

    public AuthController(AccountStore accountStore, TokenService tokenService, FailureTracker failureTracker) {
        this.accountStore = accountStore;
        this.tokenService = tokenService;
        this.failureTracker = failureTracker;
    }

    public record LoginRequest(String username, String password) {
    }

    public record TokenRequest(String token) {
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody LoginRequest request,
                                                     HttpServletRequest http) {
        String source = sourceOf(http);
        LockStatus lock = failureTracker.status(request.username(), source);
        if (lock.locked()) {
            // 锁定期间即使凭据正确也按锁定原因拒绝。
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(body(
                    "result", "DENY_LOCKED",
                    "reason", "account+source temporarily locked",
                    "lockedUntil", lock.lockedUntil().toString()));
        }
        if (!accountStore.verifyPassword(request.username(), request.password())) {
            LockStatus after = failureTracker.onFailure(request.username(), source);
            Map<String, Object> body = body(
                    "result", "DENY_BAD_CREDENTIALS",
                    "reason", "username or password incorrect",
                    "failures", after.failures());
            if (after.locked()) {
                body.put("lockedUntil", after.lockedUntil().toString());
            }
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(body);
        }
        failureTracker.onSuccess(request.username(), source);
        AccessToken token = tokenService.issue(request.username());
        return ResponseEntity.ok(body(
                "result", "OK",
                "token", token.value(),
                "expiresAt", token.expiresAt().toString()));
    }

    @PostMapping("/refresh")
    public ResponseEntity<Map<String, Object>> refresh(@RequestBody TokenRequest request) {
        RefreshResult result = tokenService.refresh(request.token());
        if (!result.isSuccess()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(body(
                    "result", "DENY_" + result.status(),
                    "reason", "refresh rejected: " + result.status()));
        }
        return ResponseEntity.ok(body(
                "result", "OK",
                "token", result.token().value(),
                "expiresAt", result.token().expiresAt().toString()));
    }

    @PostMapping("/revoke")
    public ResponseEntity<Map<String, Object>> revoke(@RequestBody TokenRequest request) {
        boolean revoked = tokenService.revoke(request.token());
        return ResponseEntity.ok(body("result", revoked ? "REVOKED" : "NOT_REVOKED"));
    }

    private static String sourceOf(HttpServletRequest http) {
        String header = http.getHeader("X-Source");
        return header != null && !header.isBlank() ? header : http.getRemoteAddr();
    }

    private static Map<String, Object> body(Object... kv) {
        Map<String, Object> map = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            map.put((String) kv[i], kv[i + 1]);
        }
        return map;
    }
}
