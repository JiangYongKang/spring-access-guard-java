package com.github.highcumontoa.springaccessguardjava.security.token;

/**
 * 刷新结果：成功时携带新凭据；失败时携带可区分的原因状态。
 *
 * @param status 刷新时旧凭据的校验结论（VALID 表示刷新成功）
 * @param token  新签发的凭据，失败时为 null
 */
public record RefreshResult(TokenStatus status, AccessToken token) {

    public boolean isSuccess() {
        return status == TokenStatus.VALID && token != null;
    }
}
