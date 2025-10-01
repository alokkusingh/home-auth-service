package com.alok.security.model.oauth2;

public record TokenSuccessResponse(
        String accessToken, TokenType tokenType, Scope scope, Integer expiresIn, String issuer,
        String refreshToken
) implements TokenResponse {
}
