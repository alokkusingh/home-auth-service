package com.alok.security.oauth2.google.service;

import com.alok.security.model.UserInfo;
import com.alok.security.model.UserRole;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.naming.AuthenticationException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Collections;

@Service
public class GoogleTokenValidatorService {


    private String goggleOauthClientId;

    private GoogleIdTokenVerifier verifier;

    public GoogleTokenValidatorService(@Value("${oauth.google.client.id}") String goggleOauthClientId) throws GeneralSecurityException, IOException {
        this.goggleOauthClientId = goggleOauthClientId;

        System.out.println("goggleOauthClientId: " + this.goggleOauthClientId);
        verifier = new GoogleIdTokenVerifier.Builder(GoogleNetHttpTransport.newTrustedTransport(), JacksonFactory.getDefaultInstance())
                // Specify the CLIENT_ID of the app that accesses the backend:
                .setAudience(Collections.singletonList(this.goggleOauthClientId))
                // Or, if multiple clients access the backend:
                //.setAudience(Arrays.asList(CLIENT_ID_1, CLIENT_ID_2, CLIENT_ID_3)
                .build();
    }


    public UserInfo validateIdToken(String idTokenString) throws AuthenticationException, GeneralSecurityException, IOException {
        GoogleIdToken idToken = verifier.verify(idTokenString);
        if (idToken != null) {
            GoogleIdToken.Payload payload = idToken.getPayload();

            // Print user identifier
            String userId = payload.getSubject();
            System.out.println("User ID: " + userId);

            // Get profile information from payload
            String email = payload.getEmail();
            boolean emailVerified = Boolean.valueOf(payload.getEmailVerified());
            String name = (String) payload.get("name");
            String pictureUrl = (String) payload.get("picture");
            String locale = (String) payload.get("locale");
            String familyName = (String) payload.get("family_name");
            String givenName = (String) payload.get("given_name");


            switch(email) {
                case "alok.ku.singh@gmail.com" -> {
                    return new UserInfo(userId, name, email, UserRole.ADMIN);
                }
                case "rachna2589@gmail.com" -> {
                    return new UserInfo(userId, name, email, UserRole.USER);
                }
                default -> throw new AuthenticationException(email + " is not authorized");
            }

        } else {
            System.out.println("Invalid ID token.");
            throw new AuthenticationException("Invalid ID Token");
        }

    }
}
