package com.alok.security.model.oauth2;

public sealed interface TokenResponse permits TokenSuccessResponse, TokenErrorResponse {
}
