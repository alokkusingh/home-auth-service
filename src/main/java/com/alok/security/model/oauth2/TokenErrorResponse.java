package com.alok.security.model.oauth2;

public record TokenErrorResponse(String error, String msg) implements TokenResponse {
}
