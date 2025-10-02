package com.alok.security.token.controller;

import com.alok.home.commons.dto.exception.NotABearerTokenException;
import com.alok.security.model.UserInfoResponse;
import com.alok.security.model.oauth2.*;
import com.alok.security.token.service.EmailService;
import com.alok.security.token.service.HomeTokenService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
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

    private final HomeTokenService homeTokenService;
    private final EmailService emailService;

    public HomeTokenController(HomeTokenService homeTokenService, EmailService emailService) {
        this.homeTokenService = homeTokenService;
        this.emailService = emailService;
    }

    @PostMapping("/validate")
    public ResponseEntity<UserInfoResponse> validateToken(
            @RequestHeader("Authorization") String bearerToken,
            @RequestHeader(value = "subject", required = false) String subject,
            @RequestHeader(value = "audience", required = false, defaultValue = "home-stack") String audience
    ) {

        String token;
        if (bearerToken != null && bearerToken.startsWith("Bearer")) {
            token = bearerToken.substring(7);
        } else {
            emailService.sendEmail("Unauthenticated Access Alert", "Tried to access Home Stack API without a Bearer token");
            throw new NotABearerTokenException("Token is not a valid Bearer token");
        }

        return ResponseEntity
                .ok()
                .body(homeTokenService.validateToken(token, subject, audience));
    }

    @PostMapping("/generate")
    public ResponseEntity<TokenResponse> generateToken(
            @RequestHeader("grant-type") GrantType grantType,
            @RequestHeader("scope") Scope scope,
            @RequestHeader("audience") String audience,
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
            case token_exchange -> {
                return ResponseEntity
                        .unprocessableEntity()
                        .body(new TokenErrorResponse("unsupported_grant_type", "The token_exchange grant type is not supported for Basic Auth"));
            }
            default -> throw new InvalidParameterException("invalid_grant: only client_credentials grant is supported");
        }
    }

    @PostMapping("/exchange")
    public ResponseEntity<TokenResponse> exchangeToken(
            @RequestHeader("Authorization") String bearerToken,
            @RequestHeader(value = "token-provider", required = false) TokenProvider tokenProvider,
            @RequestHeader("grant-type") GrantType grantType,
            @RequestHeader(value = "audience", required = false, defaultValue = "home-stack") String audience,
            @RequestHeader(value = "secure", required = false, defaultValue = "true") Boolean secure,
            HttpServletResponse response
    ) throws AuthenticationException, GeneralSecurityException, IOException {

        String token;
        if (bearerToken != null && bearerToken.startsWith("Bearer")) {
            token = bearerToken.substring(7);
        } else {
            emailService.sendEmail("Unauthenticated Access Alert", "Tried to access Home Stack API without a Bearer token");
            throw new NotABearerTokenException("Token is not a valid Bearer token");
        }

        return switch (grantType) {
            case token_exchange -> {
                TokenSuccessResponse tokenResponse = (TokenSuccessResponse) homeTokenService.exchangeAccessTokenUsingIdToken(
                        token,
                        tokenProvider,
                        audience
                );

                // Set token in cookie
                var cookie = new Cookie("HOME_STACK_ACCESS_TOKEN", tokenResponse.accessToken());
                cookie.setHttpOnly(true);
                cookie.setPath("/");
                cookie.setMaxAge(tokenResponse.expiresIn());
                cookie.setSecure(secure);
                response.addCookie(cookie);

                cookie = new Cookie("TOKEN_SCOPE", "user");
                cookie.setHttpOnly(true);
                cookie.setPath("/");
                cookie.setMaxAge(tokenResponse.expiresIn());
                cookie.setSecure(secure);
                response.addCookie(cookie);

                // For security reasons, do not set the REFRESH_TOKEN in cookie, to minimize network exposer of refresh token

                yield ResponseEntity
                        .ok()
                        .body(tokenResponse);
            }
            case refresh_token -> ResponseEntity
                    .ok()
                    .body(homeTokenService.exchangeAccessTokenUsingRefreshToken(token));
            case client_credentials -> ResponseEntity
                    .unprocessableEntity()
                    .body(new TokenErrorResponse("unsupported_grant_type", "The client_credentials grant type is not supported for exchange"));
        };
    }
}
