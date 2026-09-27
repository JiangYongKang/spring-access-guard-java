package com.github.highcumontoa.springaccessguardjava.security;

/**
 * 角色模型：角色之间存在包含关系，ADMIN 隐含 USER 的权限。
 */
public enum Role {
    USER,
    ADMIN;

    /**
     * 当前角色是否满足所需角色。
     */
    public boolean covers(Role required) {
        // 枚举声明顺序即权限层级：ADMIN 覆盖 USER。
        return this.ordinal() >= required.ordinal();
    }
}
