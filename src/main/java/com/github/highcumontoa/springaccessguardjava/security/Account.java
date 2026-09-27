package com.github.highcumontoa.springaccessguardjava.security;

import java.util.Set;

/**
 * 本地账号：用户名、口令散列与实时角色集合。
 * 授权判定读取的是账号当前角色，因此角色调整立即生效且语义稳定。
 */
public class Account {

    private final String username;
    private final String passwordHash;
    private volatile Set<Role> roles;

    public Account(String username, String passwordHash, Set<Role> roles) {
        this.username = username;
        this.passwordHash = passwordHash;
        this.roles = roles;
    }

    public String getUsername() {
        return username;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }
}
