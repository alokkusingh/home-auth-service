package com.alok.security.oauth2.google.controller;

import com.alok.home.commons.exception.NotABearerTokenException;
import com.alok.security.model.UserInfo;
import com.alok.security.oauth2.google.service.GoogleTokenValidatorService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.naming.AuthenticationException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidParameterException;

@RequestMapping("/google/validate")
@RestController
public class GoogleTokenValidatorController {

    private GoogleTokenValidatorService googleTokenValidatorService;

    public GoogleTokenValidatorController(GoogleTokenValidatorService googleTokenValidatorService) {
        this.googleTokenValidatorService = googleTokenValidatorService;
    }

    @PostMapping("/id-token")
    public ResponseEntity<UserInfo> validateIdToken(@RequestHeader("Authorization") String bearerToken) throws AuthenticationException, GeneralSecurityException, IOException {

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
