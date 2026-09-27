package com.github.highcumontoa.springaccessguardjava.tests;

import com.github.highcumontoa.springaccessguardjava.security.crypto.PasswordHasher;
import com.github.highcumontoa.springaccessguardjava.security.model.Account;
import com.github.highcumontoa.springaccessguardjava.security.store.AccountStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Set;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Full-stack checks: the same reasons reach every entry point as distinct HTTP
 * statuses and distinct machine-readable {@code reason} fields.
 */
@SpringBootTest
@AutoConfigureMockMvc
class HttpEndpointsIntegrationTest {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private AccountStore accounts;

    @Autowired
    private PasswordHasher hasher;

    @BeforeEach
    void resetSeedAccounts() {
        // Role changes in one test must not leak into another (same context).
        accounts.put(new Account("admin", hasher.hash("admin123"),
                Set.of("admin", "user"), true));
        accounts.put(new Account("user", hasher.hash("user123"),
                Set.of("user"), true));
    }

    @Test
    void loginAndAccessHappyPath() throws Exception {
        String token = login("user", "user123");

        mvc.perform(get("/api/profile").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.subject").value("user"));

        mvc.perform(get("/api/admin/panel").header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.reason").value("FORBIDDEN"));
    }

    @Test
    void missingTokenAndBadSignatureHaveDistinctBodiesButBoth401() throws Exception {
        mvc.perform(get("/api/profile"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("MISSING_TOKEN"));

        mvc.perform(get("/api/profile").header("Authorization", "Bearer abc.def"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("BAD_SIGNATURE"));

        mvc.perform(get("/api/profile").header("Authorization", "Basic xyz"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("MISSING_TOKEN"));
    }

    @Test
    void malformedTokenIsMALFORMED() throws Exception {
        mvc.perform(get("/api/profile").header("Authorization", "Bearer no-dot-here"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("MALFORMED_TOKEN"));
    }

    @Test
    void badPasswordIs401WithBAD_CREDENTIALS() throws Exception {
        mvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"user\",\"password\":\"nope\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("BAD_CREDENTIALS"));
    }

    @Test
    void adminCanPromoteUserViaLiveRoles() throws Exception {
        String admin = login("admin", "admin123");
        String user = login("user", "user123");

        // before promotion forbidden
        mvc.perform(get("/api/admin/panel").header("Authorization", "Bearer " + user))
                .andExpect(status().isForbidden());

        mvc.perform(post("/api/admin/roles")
                        .header("Authorization", "Bearer " + admin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"user\",\"roles\":[\"user\",\"admin\"]}"))
                .andExpect(status().isOk());

        // same already-issued token now passes
        mvc.perform(get("/api/admin/panel").header("Authorization", "Bearer " + user))
                .andExpect(status().isOk());
    }

    @Test
    void revokedTokenReturns401_REVOKED() throws Exception {
        String token = login("user", "user123");
        mvc.perform(post("/auth/logout").header("Authorization", "Bearer " + token))
                .andExpect(status().isNoContent());
        mvc.perform(get("/api/profile").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("REVOKED"));
    }

    private String login(String username, String password) throws Exception {
        String response = mvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"password\":\""
                                + password + "\"}"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        int i = response.indexOf("\"token\":\"");
        int start = i + "\"token\":\"".length();
        int end = response.indexOf("\"", start);
        return response.substring(start, end);
    }
}
