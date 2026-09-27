package com.github.highcumontoa.springaccessguardjava.web;

import com.github.highcumontoa.springaccessguardjava.security.store.AccountStore;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Demo operations guarded by roles:
 * <ul>
 *   <li>{@code GET /api/profile} — any authenticated account</li>
 *   <li>{@code GET /api/admin/panel} — requires {@code admin}</li>
 * </ul>
 * Role changes ({@code POST /api/admin/roles}) demonstrate the live-role
 * semantics: they affect already-issued tokens immediately.
 */
@RestController
@RequestMapping("/api")
public class ProtectedController {

    private final AccountStore accounts;

    public ProtectedController(AccountStore accounts) {
        this.accounts = accounts;
    }

    /** Any authenticated caller (no specific role required). */
    @RequireRole("")
    @GetMapping("/profile")
    public Map<String, Object> profile(HttpServletRequest request) {
        return Map.of(
                "subject", request.getAttribute("access.subject"),
                "roles", request.getAttribute("access.roles"));
    }

    /** Only callers currently holding the admin role. */
    @RequireRole("admin")
    @GetMapping("/admin/panel")
    public Map<String, Object> adminPanel(HttpServletRequest request) {
        return Map.of(
                "message", "welcome to the admin panel",
                "subject", request.getAttribute("access.subject"));
    }

    /** Admin-only: replace an account's role set. Takes effect immediately. */
    @RequireRole("admin")
    @PostMapping("/admin/roles")
    public ResponseEntity<Map<String, Object>> updateRoles(@RequestBody RoleUpdate body) {
        Set<String> roles = body.roles() == null ? Set.of() : Set.copyOf(body.roles());
        boolean updated = accounts.updateRoles(body.username(), roles);
        if (!updated) {
            throw new AccessDeniedException(
                    com.github.highcumontoa.springaccessguardjava.security.decision.RejectionReason.FORBIDDEN,
                    "account not found: " + body.username());
        }
        return ResponseEntity.ok(Map.of("username", body.username(), "roles", roles));
    }

    public record RoleUpdate(String username, List<String> roles) {
    }
}
