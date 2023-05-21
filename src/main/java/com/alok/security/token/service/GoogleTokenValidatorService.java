package com.alok.security.token.service;

import com.alok.home.commons.exception.InvalidTokenException;
import com.alok.home.commons.exception.UserNotAuthorizedException;
import com.alok.security.dao.User;
import com.alok.security.model.UserInfoResponse;
import com.alok.security.repository.UserRepository;
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
    private UserRepository userRepository;

    public GoogleTokenValidatorService(
            @Value("${oauth.google.client.id}") String goggleOauthClientId,
            UserRepository userRepository) throws GeneralSecurityException, IOException {
        this.goggleOauthClientId = goggleOauthClientId;
        this.userRepository = userRepository;

        System.out.println("goggleOauthClientId: " + this.goggleOauthClientId);
        verifier = new GoogleIdTokenVerifier.Builder(GoogleNetHttpTransport.newTrustedTransport(), JacksonFactory.getDefaultInstance())
                // Specify the CLIENT_ID of the app that accesses the backend:
                .setAudience(Collections.singletonList(this.goggleOauthClientId))
                // Or, if multiple clients access the backend:
                //.setAudience(Arrays.asList(CLIENT_ID_1, CLIENT_ID_2, CLIENT_ID_3)
                .build();
    }


    public UserInfoResponse validateIdToken(String idTokenString) throws AuthenticationException, GeneralSecurityException, IOException {
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

            User user = userRepository.getUserByEmail(email);

            if (user == null) {
                throw new UserNotAuthorizedException(email + " is not authorized");
            }

            return new UserInfoResponse(
                    userId,
                    name,
                    email,
                    user.getRoles().stream().findAny().get().getName()
            );
        } else {
            System.out.println("Invalid ID token.");
            throw new InvalidTokenException("Token is either tampered/expired/wrong audience");
        }

    }
}
