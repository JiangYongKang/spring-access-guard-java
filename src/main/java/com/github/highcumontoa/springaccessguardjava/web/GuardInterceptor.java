package com.github.highcumontoa.springaccessguardjava.web;

import com.github.highcumontoa.springaccessguardjava.security.AccessGuard;
import com.github.highcumontoa.springaccessguardjava.security.decision.AccessDecision;
import com.github.highcumontoa.springaccessguardjava.web.RequireRole;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * The single enforcement point for protected handler methods.
 *
 * <p>It extracts the {@code Authorization: Bearer <token>} header and the
 * source address, then delegates to {@link AccessGuard}, which every other
 * entry point uses as well. A handler without {@link RequireRole} is public.
 * A denial becomes {@link AccessDeniedException} carrying the distinct reason.
 */
public class GuardInterceptor implements HandlerInterceptor {

    private static final Logger log = LoggerFactory.getLogger(GuardInterceptor.class);
    private static final String BEARER_PREFIX = "Bearer ";
    private static final String UNKNOWN_SOURCE = "unknown";

    private final AccessGuard guard;

    public GuardInterceptor(AccessGuard guard) {
        this.guard = guard;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response,
                             Object handler) {
        if (!(handler instanceof HandlerMethod handlerMethod)) {
            return true;
        }
        RequireRole required = handlerMethod.getMethodAnnotation(RequireRole.class);
        if (required == null) {
            required = handlerMethod.getBeanType().getAnnotation(RequireRole.class);
        }
        if (required == null) {
            return true; // public endpoint
        }

        String rawToken = extractToken(request);
        String source = resolveSource(request);
        log.info("intercept path='{}' requiredRole='{}' source='{}' tokenPresent={}",
                request.getRequestURI(), required.value(), source, rawToken != null);

        AccessDecision decision = guard.authorize(rawToken, required.value(), source);
        if (decision instanceof AccessDecision.Allowed allowed) {
            request.setAttribute("access.subject", allowed.subject());
            request.setAttribute("access.roles", allowed.roles());
            return true;
        }
        AccessDecision.Denied denied = (AccessDecision.Denied) decision;
        throw new AccessDeniedException(denied.reason(), denied.detail());
    }

    private String extractToken(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith(BEARER_PREFIX)) {
            String token = header.substring(BEARER_PREFIX.length()).trim();
            return token.isEmpty() ? null : token;
        }
        return null;
    }

    /** First X-Forwarded-For hop, else the transport address. */
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
