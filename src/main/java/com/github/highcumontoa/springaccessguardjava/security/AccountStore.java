package com.github.highcumontoa.springaccessguardjava.security;

import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 内置账号存储（内存实现），同时承担口令校验职责。
 * 预置两个演示账号：alice(USER) / admin(ADMIN)。
 */
public class AccountStore {

    private static final String SALT = "spring-access-guard";

    private final Map<String, Account> accounts = new ConcurrentHashMap<>();

    public AccountStore() {
        register("alice", "alice-pass", Set.of(Role.USER));
        register("admin", "admin-pass", Set.of(Role.ADMIN, Role.USER));
    }

    public void register(String username, String rawPassword, Set<Role> roles) {
        accounts.put(username, new Account(username, Passwords.hash(rawPassword, SALT), Set.copyOf(roles)));
    }

    public Optional<Account> find(String username) {
        return Optional.ofNullable(accounts.get(username));
    }

    public boolean verifyPassword(String username, String rawPassword) {
        return find(username)
                .map(account -> Passwords.matches(rawPassword, SALT, account.getPasswordHash()))
                .orElse(false);
    }

    /**
     * 调整账号角色。授权判定读取实时角色，调整后立即生效。
     */
    public void updateRoles(String username, Set<Role> newRoles) {
        Account account = accounts.get(username);
        if (account != null) {
            account.setRoles(Set.copyOf(newRoles));
        }
    }
}
