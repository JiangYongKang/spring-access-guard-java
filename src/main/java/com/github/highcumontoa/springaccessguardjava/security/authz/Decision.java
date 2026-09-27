package com.github.highcumontoa.springaccessguardjava.security.authz;

import com.github.highcumontoa.springaccessguardjava.security.token.TokenStatus;

/**
 * 授权判定结论：未认证与已认证但无权限必须可区分。
 */
public enum Decision {
    /** 放行 */
    ALLOW,
    /** 未通过认证（凭据缺失或无效），detail 中携带具体 TokenStatus */
    DENY_UNAUTHENTICATED,
    /** 已认证但角色不足 */
    DENY_FORBIDDEN
}
