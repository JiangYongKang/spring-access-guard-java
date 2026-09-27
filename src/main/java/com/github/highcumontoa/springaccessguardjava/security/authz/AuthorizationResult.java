package com.github.highcumontoa.springaccessguardjava.security.authz;

import com.github.highcumontoa.springaccessguardjava.security.token.TokenStatus;

/**
 * 授权判定结果，附带判定依据便于解释与日志输出。
 *
 * @param decision    判定结论
 * @param tokenStatus 认证阶段的凭据状态（未认证时给出具体原因）
 * @param username    已认证时的账号名
 * @param detail      人类可读的判定依据
 */
public record AuthorizationResult(Decision decision, TokenStatus tokenStatus,
                                  String username, String detail) {

    public boolean isAllowed() {
        return decision == Decision.ALLOW;
    }
}
