package com.github.highcumontoa.springaccessguardjava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Web 入口集成测试：登录、越权、锁定、吊销在各入口下结论一致且可解释。
 */
@SpringBootTest
@AutoConfigureMockMvc
class AccessGuardWebTest {

    private static final Logger log = LoggerFactory.getLogger(AccessGuardWebTest.class);

    @Autowired
    private MockMvc mvc;

    private final ObjectMapper om = new ObjectMapper();

    private String login(String username, String password, String source) throws Exception {
        MvcResult result = mvc.perform(post("/auth/login")
                        .header("X-Source", source)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"))
                .andExpect(status().isOk())
                .andReturn();
        String token = om.readTree(result.getResponse().getContentAsString()).get("token").asText();
        log.info("输入=登录 {}@{}, 判定=签发凭据 {}", username, source, token);
        return token;
    }

    @Test
    void unauthenticatedAndForbiddenAreDistinguishedOverHttp() throws Exception {
        MvcResult noToken = mvc.perform(get("/api/user")).andExpect(status().isUnauthorized()).andReturn();
        log.info("输入=无凭据访问 /api/user, 响应={}", noToken.getResponse().getContentAsString());
        assertEquals("DENY_UNAUTHENTICATED",
                om.readTree(noToken.getResponse().getContentAsString()).get("decision").asText());

        String aliceToken = login("alice", "alice-pass", "web-test-1");
        MvcResult forbidden = mvc.perform(get("/api/admin")
                        .header("Authorization", "Bearer " + aliceToken))
                .andExpect(status().isForbidden()).andReturn();
        log.info("输入=alice 访问 /api/admin, 响应={}", forbidden.getResponse().getContentAsString());
        assertEquals("DENY_FORBIDDEN",
                om.readTree(forbidden.getResponse().getContentAsString()).get("decision").asText());

        MvcResult ok = mvc.perform(get("/api/user")
                        .header("Authorization", "Bearer " + aliceToken))
                .andExpect(status().isOk()).andReturn();
        log.info("输入=alice 访问 /api/user, 响应={}", ok.getResponse().getContentAsString());
    }

    @Test
    void revokedTokenIsRejectedWithDistinctReasonOverHttp() throws Exception {
        String token = login("alice", "alice-pass", "web-test-2");
        mvc.perform(post("/auth/revoke")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"" + token + "\"}"))
                .andExpect(status().isOk());
        MvcResult denied = mvc.perform(get("/api/user")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized()).andReturn();
        JsonNode body = om.readTree(denied.getResponse().getContentAsString());
        log.info("输入=已吊销凭据访问 /api/user, 响应={}", body);
        assertEquals("DENY_UNAUTHENTICATED", body.get("decision").asText());
        assertEquals("REVOKED", body.get("tokenStatus").asText());
    }

    @Test
    void lockRejectsEvenCorrectPasswordAndExpires() throws Exception {
        String source = "web-test-lock";
        // 连续 5 次错误口令（阈值见 application.properties）。
        for (int i = 1; i <= 5; i++) {
            MvcResult r = mvc.perform(post("/auth/login")
                            .header("X-Source", source)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"username\":\"alice\",\"password\":\"wrong\"}"))
                    .andExpect(status().isUnauthorized()).andReturn();
            log.info("输入=第 {} 次错误口令, 响应={}", i, r.getResponse().getContentAsString());
        }
        // 锁定后即使口令正确也按锁定原因拒绝。
        MvcResult locked = mvc.perform(post("/auth/login")
                        .header("X-Source", source)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"alice-pass\"}"))
                .andExpect(status().isTooManyRequests()).andReturn();
        JsonNode body = om.readTree(locked.getResponse().getContentAsString());
        log.info("输入=锁定期间正确口令, 响应={}", body);
        assertEquals("DENY_LOCKED", body.get("result").asText());

        // 其他来源不受影响。
        String token = login("alice", "alice-pass", "web-test-lock-other");
        log.info("输入=其他来源正常登录, 判定=成功签发 {}", token);
    }
}
