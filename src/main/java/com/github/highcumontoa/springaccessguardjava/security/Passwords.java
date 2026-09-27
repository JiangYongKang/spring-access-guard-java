package com.github.highcumontoa.springaccessguardjava.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * 口令散列工具（ salted SHA-256 ）。
 */
public final class Passwords {

    private Passwords() {
    }

    public static String hash(String rawPassword, String salt) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashed = digest.digest((salt + ":" + rawPassword).getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hashed);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    public static boolean matches(String rawPassword, String salt, String expectedHash) {
        String actual = hash(rawPassword, salt);
        // 常量时间比较，避免时序侧信道。
        return MessageDigest.isEqual(actual.getBytes(StandardCharsets.UTF_8),
                expectedHash.getBytes(StandardCharsets.UTF_8));
    }
}
