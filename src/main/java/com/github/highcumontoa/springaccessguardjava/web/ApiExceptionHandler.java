package com.github.highcumontoa.springaccessguardjava.web;

import com.github.highcumontoa.springaccessguardjava.security.decision.RejectionReason;
import com.github.highcumontoa.springaccessguardjava.web.dto.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Clock;
import java.time.Instant;

/**
 * Maps distinct {@link RejectionReason}s to distinct HTTP statuses, so clients
 * can tell failure modes apart instead of getting one generic 401:
 *
 * <ul>
 *   <li>401 UNAUTHORIZED: missing/malformed/bad-signature/expired/revoked/
 *       unknown/reused token, bad credentials, rejected refresh</li>
 *   <li>403 FORBIDDEN: authenticated but lacking the role (distinct from 401)</li>
 *   <li>423 LOCKED: (account, source) is temporarily locked</li>
 *   <li>429 TOO_MANY_REQUESTS: source rate limited</li>
 * </ul>
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

    private final Clock clock;

    public ApiExceptionHandler(Clock clock) {
        this.clock = clock;
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handle(AccessDeniedException ex,
                                                HttpServletRequest request) {
        RejectionReason reason = ex.reason();
        HttpStatus status = mapStatus(reason);
        ErrorResponse body = new ErrorResponse(
                Instant.now(clock),
                status.value(),
                status.getReasonPhrase(),
                reason.name(),
                ex.getMessage(),
                request.getRequestURI());
        log.info("http decision path='{}' reason={} status={} basis='{}'",
                request.getRequestURI(), reason, status.value(), ex.getMessage());
        return ResponseEntity.status(status).body(body);
    }

    private HttpStatus mapStatus(RejectionReason reason) {
        return switch (reason) {
            case FORBIDDEN -> HttpStatus.FORBIDDEN;
            case ACCOUNT_LOCKED -> HttpStatus.LOCKED;
            case RATE_LIMITED -> HttpStatus.TOO_MANY_REQUESTS;
            default -> HttpStatus.UNAUTHORIZED;
        };
    }
}
