package com.github.highcumontoa.springaccessguardjava.security.token;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.highcumontoa.springaccessguardjava.security.decision.RejectionReason;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * HMAC-SHA256 implementation of {@link TokenSigner}.
 *
 * <p>Wire format: {@code base64url(payloadJson).base64url(hmacSha256(payload))}.
 * Parsing keeps two failure modes apart:
 * <ul>
 *   <li>structural problems (shape, base64, JSON, missing/odd claims) -> MALFORMED_TOKEN</li>
 *   <li>well-formed token whose MAC does not match -> BAD_SIGNATURE</li>
 * </ul>
 */
public class HmacTokenSigner implements TokenSigner {

    private static final String HMAC_ALGORITHM = "HmacSHA256";

    private final byte[] secret;
    private final Mac mac;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
    private final Base64.Decoder decoder = Base64.getUrlDecoder();

    public HmacTokenSigner(String secret) {
        this.secret = secret.getBytes(StandardCharsets.UTF_8);
        try {
            this.mac = Mac.getInstance(HMAC_ALGORITHM);
            this.mac.init(new SecretKeySpec(this.secret, HMAC_ALGORITHM));
        } catch (Exception e) {
            throw new IllegalStateException("Cannot initialize HMAC-SHA256 signer", e);
        }
    }

    @Override
    public Issued issue(String jti, String familyId, String subject,
                        Instant issuedAt, Instant expiresAt) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("jti", jti);
        claims.put("fam", familyId);
        claims.put("sub", subject);
        claims.put("iat", issuedAt.toEpochMilli());
        claims.put("exp", expiresAt.toEpochMilli());
        try {
            byte[] payload = objectMapper.writeValueAsBytes(claims);
            String raw = encoder.encodeToString(payload) + "." + encoder.encodeToString(sign(payload));
            return new Issued(raw, jti, familyId, subject, issuedAt, expiresAt);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to sign token", e);
        }
    }

    private byte[] sign(byte[] payload) {
        try {
            Mac m = Mac.getInstance(HMAC_ALGORITHM);
            m.init(new SecretKeySpec(secret, HMAC_ALGORITHM));
            return m.doFinal(payload);
        } catch (Exception e) {
            throw new IllegalStateException("HMAC failure", e);
        }
    }

    @Override
    public ParseResult parse(String raw) {
        if (raw == null || raw.isBlank()) {
            return new ParseResult.Bad(RejectionReason.MISSING_TOKEN, "token is empty");
        }
        int dot = raw.indexOf('.');
        // exactly one separator, both sections non-empty
        if (dot <= 0 || dot == raw.length() - 1 || raw.indexOf('.', dot + 1) != -1) {
            return new ParseResult.Bad(RejectionReason.MALFORMED_TOKEN,
                    "token must be payload.signature");
        }
        String payloadPart = raw.substring(0, dot);
        String signaturePart = raw.substring(dot + 1);

        byte[] payload;
        byte[] signature;
        try {
            payload = decoder.decode(payloadPart);
            signature = decoder.decode(signaturePart);
        } catch (IllegalArgumentException e) {
            return new ParseResult.Bad(RejectionReason.MALFORMED_TOKEN,
                    "token sections are not valid base64url");
        }

        // Constant-time MAC comparison. A structurally valid token with a wrong
        // MAC is BAD_SIGNATURE, distinct from malformed input.
        byte[] expected = sign(payload);
        if (!MessageDigest.isEqual(expected, signature)) {
            return new ParseResult.Bad(RejectionReason.BAD_SIGNATURE,
                    "signature does not match payload");
        }

        JsonNode node;
        try {
            node = objectMapper.readTree(payload);
        } catch (Exception e) {
            return new ParseResult.Bad(RejectionReason.MALFORMED_TOKEN,
                    "payload is not valid JSON");
        }
        if (!node.hasNonNull("jti") || !node.hasNonNull("fam") || !node.hasNonNull("sub")
                || !node.hasNonNull("iat") || !node.hasNonNull("exp")) {
            return new ParseResult.Bad(RejectionReason.MALFORMED_TOKEN,
                    "payload is missing required claims");
        }
        try {
            String jti = node.get("jti").asText();
            String familyId = node.get("fam").asText();
            String subject = node.get("sub").asText();
            Instant iat = Instant.ofEpochMilli(node.get("iat").asLong());
            Instant exp = Instant.ofEpochMilli(node.get("exp").asLong());
            if (jti.isBlank() || subject.isBlank() || exp.isBefore(iat)) {
                return new ParseResult.Bad(RejectionReason.MALFORMED_TOKEN,
                        "payload contains nonsensical claims");
            }
            return new ParseResult.Ok(jti, familyId, subject, iat, exp);
        } catch (RuntimeException e) {
            return new ParseResult.Bad(RejectionReason.MALFORMED_TOKEN,
                    "claim values have wrong types: " + e.getMessage());
        }
    }
}
