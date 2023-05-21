package com.alok.security.token.controller;

import com.alok.home.commons.exception.NotABearerTokenException;
import com.alok.security.model.ApplicationInfoResponse;
import com.alok.security.model.oauth2.GrantType;
import com.alok.security.model.oauth2.Scope;
import com.alok.security.model.oauth2.TokenResponse;
import com.alok.security.token.service.HomeTokenService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.naming.AuthenticationException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidParameterException;
import java.security.Principal;

@RequestMapping("/home/token")
@RestController
public class HomeTokenController {

    private HomeTokenService homeTokenService;

    public HomeTokenController(HomeTokenService homeTokenService) {
        this.homeTokenService = homeTokenService;
    }

    @PostMapping("/validate")
    public ResponseEntity<ApplicationInfoResponse> validateToken(
            @RequestHeader("Authorization") String bearerToken,
            @RequestHeader("subject") String subject,
            @RequestHeader("audience") String audience
    ) throws AuthenticationException, GeneralSecurityException, IOException {

        String token = null;
        if (bearerToken != null && bearerToken.startsWith("Bearer")) {
            token = bearerToken.substring(7);
        } else {
            throw new NotABearerTokenException("Token is not a valid Bearer token");
        }

        return ResponseEntity
                .ok()
                .body(new ApplicationInfoResponse(
                        subject,
                        homeTokenService.validateToken(token, subject, audience)
                ));
    }

    @PostMapping("/generate")
    public ResponseEntity<TokenResponse> generateToken(
            @RequestHeader("grant_type") GrantType grantType,
            @RequestHeader("scope") Scope scope,
            Principal principal
    ) {

        switch (grantType) {
            case client_credentials -> {
                return ResponseEntity
                        .ok()
                        .body(homeTokenService.generateClientAccessToken(
                                principal.getName(),
                                ((Authentication) principal).getAuthorities(),
                                scope
                        ));
            }
            default -> throw new InvalidParameterException("invalid_grant: only client_credentials grant is supported");
        }
    }
}
