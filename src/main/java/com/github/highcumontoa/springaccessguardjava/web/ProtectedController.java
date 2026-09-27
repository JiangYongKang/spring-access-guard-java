package com.github.highcumontoa.springaccessguardjava.web;

import com.github.highcumontoa.springaccessguardjava.security.Role;
import com.github.highcumontoa.springaccessguardjava.security.authz.AuthorizationResult;
import com.github.highcumontoa.springaccessguardjava.security.authz.AuthorizationService;
import com.github.highcumontoa.springaccessguardjava.security.authz.Decision;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 受保护操作入口：按角色做授权判定。
 * 未认证返回 401，已认证但角色不足返回 403，二者可区分。
 */
@RestController
@RequestMapping("/api")
public class ProtectedController {

    private final AuthorizationService authorizationService;

    public ProtectedController(AuthorizationService authorizationService) {
        this.authorizationService = authorizationService;
    }

    @GetMapping("/user")
    public ResponseEntity<Map<String, Object>> userEndpoint(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        return guarded(authorization, Role.USER, "user-resource");
    }

    @GetMapping("/admin")
    public ResponseEntity<Map<String, Object>> adminEndpoint(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        return guarded(authorization, Role.ADMIN, "admin-resource");
    }

    private ResponseEntity<Map<String, Object>> guarded(String authorization, Role required, String resource) {
        String tokenValue = extractBearer(authorization);
        AuthorizationResult result = authorizationService.authorize(tokenValue, required);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("decision", result.decision().name());
        body.put("detail", result.detail());
        if (result.isAllowed()) {
            body.put("resource", resource);
            body.put("username", result.username());
            return ResponseEntity.ok(body);
        }
        if (result.tokenStatus() != null) {
            body.put("tokenStatus", result.tokenStatus().name());
        }
        HttpStatus status = result.decision() == Decision.DENY_UNAUTHENTICATED
                ? HttpStatus.UNAUTHORIZED : HttpStatus.FORBIDDEN;
        return ResponseEntity.status(status).body(body);
    }

    private static String extractBearer(String authorization) {
        if (authorization != null && authorization.startsWith("Bearer ")) {
            return authorization.substring("Bearer ".length()).trim();
        }
        return null; // 缺失或非法头按格式不合法处理
    }
}
