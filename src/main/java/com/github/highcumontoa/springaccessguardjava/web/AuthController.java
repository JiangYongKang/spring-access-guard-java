package com.github.highcumontoa.springaccessguardjava.web;

import com.github.highcumontoa.springaccessguardjava.security.AccessGuard;
import com.github.highcumontoa.springaccessguardjava.security.decision.LoginDecision;
import com.github.highcumontoa.springaccessguardjava.security.decision.RefreshDecision;
import com.github.highcumontoa.springaccessguardjava.web.dto.LoginRequest;
import com.github.highcumontoa.springaccessguardjava.web.dto.TokenResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Token endpoints, all routed through the same {@link AccessGuard}. */
@RestController
@RequestMapping("/auth")
public class AuthController {

    private static final String BEARER_PREFIX = "Bearer ";
    private static final String UNKNOWN_SOURCE = "unknown";

    private final AccessGuard guard;

    public AuthController(AccessGuard guard) {
        this.guard = guard;
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@RequestBody LoginRequest body,
                                               HttpServletRequest request) {
        LoginDecision decision = guard.login(body.username(), body.password(),
                resolveSource(request));
        if (decision instanceof LoginDecision.Success success) {
            return ResponseEntity.ok(TokenResponse.of(success.token(), success.claims()));
        }
        LoginDecision.Failure failure = (LoginDecision.Failure) decision;
        throw new AccessDeniedException(failure.reason(), failure.detail());
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(HttpServletRequest request) {
        String raw = extractToken(request);
        RefreshDecision decision = guard.refresh(raw, resolveSource(request));
        if (decision instanceof RefreshDecision.Rotated rotated) {
            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(TokenResponse.of(rotated.newToken(), rotated.claims()));
        }
        RefreshDecision.Rejected rejected = (RefreshDecision.Rejected) decision;
        throw new AccessDeniedException(rejected.reason(), rejected.detail());
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request) {
        guard.logout(extractToken(request));
        return ResponseEntity.noContent().build();
    }

    private String extractToken(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith(BEARER_PREFIX)) {
            String token = header.substring(BEARER_PREFIX.length()).trim();
            return token.isEmpty() ? null : token;
        }
        return null;
    }

    private String resolveSource(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            int comma = forwarded.indexOf(',');
            String hop = (comma > 0 ? forwarded.substring(0, comma) : forwarded).trim();
            return hop.isEmpty() ? UNKNOWN_SOURCE : hop;
        }
        String remote = request.getRemoteAddr();
        return remote == null ? UNKNOWN_SOURCE : remote;
    }
}
