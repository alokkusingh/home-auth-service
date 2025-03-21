package com.alok.security.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;
import com.alok.home.commons.security.HomeAuthTokenInterceptor;

@Configuration
public class RestClientConfig {

    @Value("${application.id}")
    private String clientId;

    @Value("${application.secret}")
    private String applicationSecret;

    @Bean
    RestTemplateBuilder restTemplateBuilder() {
        return new RestTemplateBuilder();
    }

    @Bean
    public RestTemplate emailRestTemplate(
            RestTemplateBuilder restTemplateBuilder,
            @Value("${email.token.issuer}") String emailTokenIssuer,
            @Value("${email.token.url}") String emailTokenIssuerUrl,
            @Value("${email.token.scope}") String emailTokenScope,
            @Value("${email.token.audience}") String emailTokenAudience
    ) {
        return restTemplateBuilder.interceptors(homeAuthTokenInterceptor(
                        emailTokenIssuer, emailTokenIssuerUrl, emailTokenScope, emailTokenAudience,
                        clientId, applicationSecret
                ))
                .build();
    }

    private HomeAuthTokenInterceptor homeAuthTokenInterceptor(
            String tokenIssuer,
            String tokenIssuerUrl,
            String tokenScope,
            String tokenAudience,
            String clientId,
            String applicationSecret
    ) {
        return new HomeAuthTokenInterceptor(tokenIssuer, tokenIssuerUrl, tokenScope, tokenAudience, clientId, applicationSecret);
    }
}
