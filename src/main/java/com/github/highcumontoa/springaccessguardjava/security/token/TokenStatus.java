package com.github.highcumontoa.springaccessguardjava.security.token;

/**
 * 凭据校验结论，各类失败原因必须可区分。
 */
public enum TokenStatus {
    /** 校验通过 */
    VALID,
    /** 格式不合法（结构、编码错误） */
    MALFORMED,
    /** 签名不匹配或并非本服务签发（被篡改/伪造） */
    TAMPERED,
    /** 签名有效但已过有效期 */
    EXPIRED,
    /** 签名有效但已被吊销（含被刷新轮换掉的旧凭据） */
    REVOKED
}
