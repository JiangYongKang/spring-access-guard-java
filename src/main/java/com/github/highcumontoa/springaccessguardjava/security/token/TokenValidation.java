package com.github.highcumontoa.springaccessguardjava.security.token;

/**
 * 凭据校验结果。
 *
 * @param status   校验结论
 * @param username 仅当 VALID 时非空
 * @param tokenId  可解析出 id 时非空（用于审计）
 */
public record TokenValidation(TokenStatus status, String username, String tokenId) {

    public static TokenValidation of(TokenStatus status, String username, String tokenId) {
        return new TokenValidation(status, username, tokenId);
    }

    public boolean isValid() {
        return status == TokenStatus.VALID;
    }
}
