package com.practice.rin.jwt;

import com.google.common.net.HttpHeaders;
import lombok.*;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "application.jwt")
public class JwtConfig {

    private String secretKey;
    private String tokenPrefix;
    private Integer tokenExpirationAfterDays;


    public String getAuthorizationHeader() {
        return HttpHeaders.AUTHORIZATION;
    }
}
