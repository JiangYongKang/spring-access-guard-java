package com.github.highcumontoa.springaccessguardjava.config;

import com.github.highcumontoa.springaccessguardjava.web.GuardInterceptor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/** Registers the access guard interceptor. */
@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    private final GuardInterceptor guardInterceptor;

    public WebMvcConfig(GuardInterceptor guardInterceptor) {
        this.guardInterceptor = guardInterceptor;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(guardInterceptor);
    }
}
