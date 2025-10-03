package com.alok.security.token.controller;

import com.alok.home.commons.dto.exception.NotABearerTokenException;
import com.alok.home.commons.dto.exception.UserNotAuthenticatedException;
import com.alok.home.commons.dto.exception.UserNotAuthorizedException;
import com.alok.security.model.UserInfoResponse;
import com.alok.security.model.oauth2.*;
import com.alok.security.token.service.EmailService;
import com.alok.security.token.service.HomeTokenService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

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
            //emailService.sendEmail("Unauthenticated Access Alert", "Tried to access Home Stack API without a Bearer token");
            throw new UserNotAuthenticatedException("Token not provided");
        }

        return ResponseEntity
                .ok()
                .body(homeTokenService.validateToken(token, subject, audience));
    }

    @GetMapping("/validate")
    public ResponseEntity<UserInfoResponse> validateToken(
            @RequestHeader(value = "subject", required = false) String subject,
            @RequestHeader(value = "audience", required = false, defaultValue = "home-stack") String audience,
            HttpServletRequest request
    ) {

        String bearerToken = null;
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (cookie.getName().equals("HOME_STACK_ACCESS_TOKEN")) {
                    bearerToken = cookie.getValue();
                    break;
                }
            }
        }
        if (bearerToken == null) {
            //emailService.sendEmail("Unauthenticated Access Alert", "Tried to access Home Stack API without a Bearer token");
            throw new UserNotAuthenticatedException("Token not provided in Cookie");
        }

        return ResponseEntity
                .ok()
                .body(homeTokenService.validateToken(bearerToken, subject, audience));
    }

    @PostMapping("/logout")
    public ResponseEntity<UserInfoResponse> logout(
            HttpServletRequest request,
            HttpServletResponse response
    ) {

        String bearerToken = null;
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (cookie.getName().equals("HOME_STACK_ACCESS_TOKEN")) {
                    bearerToken = cookie.getValue();
                    break;
                }
            }
        }
        if (bearerToken == null) {
            //emailService.sendEmail("Unauthenticated Access Alert", "Tried to access Home Stack API without a Bearer token");
            throw new UserNotAuthenticatedException("Token not provided in Cookie");
        }

        homeTokenService.validateToken(bearerToken, null, null);

        // Set token in cookie
        var cookie = new Cookie("HOME_STACK_ACCESS_TOKEN", "");
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge(0); // 30 minutes
        cookie.setSecure(true);
        response.addCookie(cookie);

        cookie = new Cookie("HOME_STACK_REFRESH_TOKEN", "");
        cookie.setHttpOnly(true);
        cookie.setPath("/home/auth/home/token/refresh");
        cookie.setMaxAge(0); // 2 days
        cookie.setSecure(true);
        response.addCookie(cookie);

        cookie = new Cookie("TOKEN_SCOPE", "");
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge(0); // 30 minutes
        cookie.setSecure(true);
        response.addCookie(cookie);

        return ResponseEntity.ok().build();
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
            default -> throw new InvalidParameterException("invalid_grant: only client_credentials grant is supported for generate");
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
    ) throws GeneralSecurityException, IOException {

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
                cookie.setMaxAge(1800); // 30 minutes
                cookie.setSecure(secure);
                response.addCookie(cookie);

                cookie = new Cookie("HOME_STACK_REFRESH_TOKEN", tokenResponse.refreshToken());
                cookie.setHttpOnly(true);
                cookie.setPath("/home/auth/home/token/refresh");
                // TODO: take it by calculating from refresh token expiry time
                cookie.setMaxAge(86400 * 2); // 2 days
                cookie.setSecure(secure);
                response.addCookie(cookie);

                cookie = new Cookie("TOKEN_SCOPE", "user");
                cookie.setHttpOnly(true);
                cookie.setPath("/");
                cookie.setMaxAge(1800); // 30 minutes
                cookie.setSecure(secure);
                response.addCookie(cookie);

                yield ResponseEntity
                        .ok()
                        .body(tokenResponse);
            }
            default -> throw new InvalidParameterException("invalid_grant: only token_exchange grant is supported for token exchange");
        };
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refreshToken(
            @RequestHeader("grant-type") GrantType grantType,
            @RequestHeader(value = "secure", required = false, defaultValue = "true") Boolean secure,
            HttpServletResponse response,
            HttpServletRequest request
    ) {

        String bearerToken = null;
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (cookie.getName().equals("HOME_STACK_REFRESH_TOKEN")) {
                    bearerToken = cookie.getValue();
                    break;
                }
            }
        }

        if (bearerToken == null) {
            //emailService.sendEmail("Unauthenticated Access Alert", "Tried to access Home Stack API without a Bearer token");
            throw new UserNotAuthenticatedException("Refresh Token not provided in Cookie");
        }

        return switch (grantType) {
            case refresh_token -> {
                TokenSuccessResponse tokenResponse = (TokenSuccessResponse) homeTokenService.exchangeAccessTokenUsingRefreshToken(bearerToken);

                // Set token in cookie
                var cookie = new Cookie("HOME_STACK_ACCESS_TOKEN", tokenResponse.accessToken());
                cookie.setHttpOnly(true);
                cookie.setPath("/");
                cookie.setMaxAge(1800); // 30 minutes
                cookie.setSecure(secure);
                response.addCookie(cookie);

                cookie = new Cookie("HOME_STACK_REFRESH_TOKEN", tokenResponse.refreshToken());
                cookie.setHttpOnly(true);
                cookie.setPath("/home/auth/home/token/refresh");
                cookie.setMaxAge(86400 * 2); // 2 days
                cookie.setSecure(secure);
                response.addCookie(cookie);

                cookie = new Cookie("TOKEN_SCOPE", "user");
                cookie.setHttpOnly(true);
                cookie.setPath("/");
                cookie.setMaxAge(1800); // 30 minutes
                cookie.setSecure(secure);
                response.addCookie(cookie);

                // For security reasons, do not set the REFRESH_TOKEN in cookie, to minimize network exposer of refresh token

                yield ResponseEntity
                        .ok()
                        .body(tokenResponse);
            }
            default -> throw new InvalidParameterException("invalid_grant: only refresh_token grant is supported for token refresh");
        };
    }
}
