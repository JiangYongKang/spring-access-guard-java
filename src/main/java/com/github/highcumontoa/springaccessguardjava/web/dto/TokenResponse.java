package com.github.highcumontoa.springaccessguardjava.web.dto;

import com.github.highcumontoa.springaccessguardjava.security.decision.TokenCheck;

public record TokenResponse(String token, String subject, String jti,
                            String issuedAt, String expiresAt) {

    public static TokenResponse of(String token, TokenCheck.Valid claims) {
        return new TokenResponse(token, claims.subject(), claims.jti(),
                claims.issuedAt().toString(), claims.expiresAt().toString());
    }
}
