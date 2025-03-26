package com.alok.security.token.controller;

import com.alok.home.commons.dto.exception.NotABearerTokenException;
import com.alok.security.model.UserInfoResponse;
import com.alok.security.model.oauth2.GrantType;
import com.alok.security.model.oauth2.Scope;
import com.alok.security.model.oauth2.TokenResponse;
import com.alok.security.token.service.EmailService;
import com.alok.security.token.service.HomeTokenService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.sql.DataSource;
import java.security.InvalidParameterException;
import java.security.Principal;

@RequestMapping("/home/token")
@RestController
public class HomeTokenController {

    private final HomeTokenService homeTokenService;
    private final DataSource dataSource;
    private final EmailService emailService;

    public HomeTokenController(HomeTokenService homeTokenService, DataSource dataSource, EmailService emailService) {
        this.homeTokenService = homeTokenService;
        this.dataSource = dataSource;
        this.emailService = emailService;
    }

    @PostMapping("/validate")
    public ResponseEntity<UserInfoResponse> validateToken(
            @RequestHeader("Authorization") String bearerToken,
            @RequestHeader("subject") String subject,
            @RequestHeader("audience") String audience
    ) {

        String token = null;
        if (bearerToken != null && bearerToken.startsWith("Bearer")) {
            token = bearerToken.substring(7);
        } else {
            emailService.sendEmail("Unauthenticated Access Alert", "Tried to access Home Stack API without a Bearer token");
            throw new NotABearerTokenException("Token is not a valid Bearer token");
        }

        return ResponseEntity
                .ok()
                .body(new UserInfoResponse(
                        null,
                        subject,
                        null,
                        homeTokenService.validateToken(token, subject, audience)
                ));
    }

    @PostMapping("/generate")
    public ResponseEntity<TokenResponse> generateToken(
            @RequestHeader("grant-type") GrantType grantType,
            @RequestHeader("scope") Scope scope,
            @RequestHeader(value = "audience", required = false, defaultValue = "home-stack-api") String audience,
            Principal principal
    ) {

        switch (grantType) {
            case client_credentials -> {
                return ResponseEntity
                        .ok()
                        .body(homeTokenService.generateClientAccessToken(
                                principal.getName(),
                                ((Authentication) principal).getAuthorities(),
                                scope,
                                audience
                        ));
            }
            default -> throw new InvalidParameterException("invalid_grant: only client_credentials grant is supported");
        }
    }
}
