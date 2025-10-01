package com.alok.security.model.oauth2;

public enum GrantType {
    client_credentials, // (RFC 6749 Section 4.4)
    token_exchange, // (RFC 8693)
    refresh_token // (RFC 6749 Section 6)
}
