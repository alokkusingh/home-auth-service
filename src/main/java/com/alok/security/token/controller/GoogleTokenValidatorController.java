package com.alok.security.token.controller;

import com.alok.home.commons.dto.exception.NotABearerTokenException;
import com.alok.security.model.UserInfoResponse;
import com.alok.security.token.service.GoogleTokenValidatorService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.naming.AuthenticationException;
import java.io.IOException;
import java.security.GeneralSecurityException;

@RequestMapping("/google/validate")
@RestController
public class GoogleTokenValidatorController {

    private GoogleTokenValidatorService googleTokenValidatorService;

    public GoogleTokenValidatorController(GoogleTokenValidatorService googleTokenValidatorService) {
        this.googleTokenValidatorService = googleTokenValidatorService;
    }

    @PostMapping("/id-token")
    public ResponseEntity<UserInfoResponse> validateIdToken(@RequestHeader("Authorization") String bearerToken) throws AuthenticationException, GeneralSecurityException, IOException {

        String token = null;
        if (bearerToken != null && bearerToken.startsWith("Bearer")) {
            token = bearerToken.substring(7, bearerToken.length());
        } else {
            throw new NotABearerTokenException("Token is not a valid Bearer token");
        }
        return ResponseEntity.ok()
                .body(googleTokenValidatorService.validateIdToken(token));
    }
}
