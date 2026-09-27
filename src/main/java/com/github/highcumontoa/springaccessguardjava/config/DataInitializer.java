package com.github.highcumontoa.springaccessguardjava.config;

import com.github.highcumontoa.springaccessguardjava.security.crypto.PasswordHasher;
import com.github.highcumontoa.springaccessguardjava.security.model.Account;
import com.github.highcumontoa.springaccessguardjava.security.store.AccountStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Set;

/**
 * Seeds two local demo accounts for manual verification:
 * <pre>
 *   admin / admin123  roles: admin, user
 *   user  / user123   roles: user
 * </pre>
 */
@Configuration
public class DataInitializer {

    private static final Logger log = LoggerFactory.getLogger(DataInitializer.class);

    @Bean
    public ApplicationRunner seedAccounts(AccountStore accounts, PasswordHasher hasher) {
        return args -> {
            if (accounts.size() > 0) {
                return;
            }
            accounts.put(new Account("admin", hasher.hash("admin123"),
                    Set.of("admin", "user"), true));
            accounts.put(new Account("user", hasher.hash("user123"),
                    Set.of("user"), true));
            log.info("seeded local accounts: admin/admin123, user/user123");
        };
    }
}
