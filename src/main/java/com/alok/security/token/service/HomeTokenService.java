package com.alok.security.token.service;

import com.alok.security.model.oauth2.GrantType;
import com.alok.security.model.oauth2.Scope;
import com.alok.security.model.oauth2.TokenResponse;
import com.alok.security.model.oauth2.TokenSuccessResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import java.security.InvalidParameterException;
import java.util.Collection;
import java.util.Optional;

@Service
public class HomeTokenService {


    private final Integer validity;
    private final String issuer;
    private final JwtUtilsService jwtUtilsService;

    public HomeTokenService(
            @Value("${application.security.jwt.validity}") Integer validity,
            @Value("${application.id}") String issuer,
            JwtUtilsService jwtUtilsService
    ) {
        this.validity = validity;
        this.issuer = issuer;
        this.jwtUtilsService = jwtUtilsService;
    }

    public TokenResponse generateClientAccessToken(
            String name,
            Collection<? extends GrantedAuthority> authorities,
            Scope scope,
            String audience
    ) {
        Optional<? extends GrantedAuthority> matchedScope = authorities.stream()
                .filter(grantedAuthority -> grantedAuthority
                        .getAuthority()
                        .substring(5)
                        .equals(scope.name())
                )
                .findAny();
        if (matchedScope.isEmpty()) {
            throw new InvalidParameterException("client not authorized to get token with given scope");
        }

        return new TokenSuccessResponse(jwtUtilsService.generateToken(name, scope.name(), audience), GrantType.client_credentials, scope, validity, issuer);
    }

    public String validateToken(String token, String sub, String aud) {
        return jwtUtilsService.validateToken(token, sub, aud);
    }
}
