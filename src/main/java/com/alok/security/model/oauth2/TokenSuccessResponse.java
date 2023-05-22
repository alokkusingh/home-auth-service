package com.alok.security.model.oauth2;

public record TokenSuccessResponse(String accessToken, GrantType tokenType, Scope scope, Integer expiresIn, String issuer) implements TokenResponse {
}
