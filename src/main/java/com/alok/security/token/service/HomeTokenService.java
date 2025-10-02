package com.alok.security.token.service;

import com.alok.home.commons.dto.exception.UserNotAuthorizedException;
import com.alok.home.commons.security.entity.CustomUserDetails;
import com.alok.home.commons.security.entity.UserInfo;
import com.alok.security.dao.User;
import com.alok.security.model.UserInfoResponse;
import com.alok.security.model.oauth2.*;
import com.alok.security.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import javax.naming.AuthenticationException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidParameterException;
import java.util.Collection;
import java.util.Optional;
import java.util.regex.Pattern;

@Service
public class HomeTokenService {


    private final Integer validity;
    private final String issuer;
    private final JwtUtilsService jwtUtilsService;
    private final GoogleTokenValidatorService googleTokenValidatorService;
    private final UserRepository userRepository;

    public HomeTokenService(
            @Value("${application.security.jwt.access-token.validity}") Integer validity,
            @Value("${application.id}") String issuer,
            JwtUtilsService jwtUtilsService,
            GoogleTokenValidatorService googleTokenValidatorService,
            UserRepository userRepository
    ) {
        this.validity = validity;
        this.issuer = issuer;
        this.jwtUtilsService = jwtUtilsService;
        this.googleTokenValidatorService = googleTokenValidatorService;
        this.userRepository = userRepository;
    }

    public TokenResponse generateClientAccessToken(
            String name,
            Collection<? extends GrantedAuthority> authorities,
            Scope scope,
            String audience
    ) {
        Optional<? extends GrantedAuthority> matchedScope = authorities.stream()
                .filter(grantedAuthority -> grantedAuthority
                        .getAuthority()
                        .substring(5)
                        .equals(scope.name())
                )
                .findAny();
        if (matchedScope.isEmpty()) {
            throw new InvalidParameterException("client not authorized to get token with given scope");
        }

        return new TokenSuccessResponse(jwtUtilsService.generateToken(name, scope.name(), audience), TokenType.Bearer, scope, validity, issuer, null);
    }

    public TokenResponse exchangeAccessTokenUsingIdToken(
            String idToken,
            TokenProvider tokenProvider,
            String audience
    ) throws GeneralSecurityException, IOException {

        var userInfo = switch (tokenProvider) {
            case GOOGLE -> googleTokenValidatorService.validateIdTokenAndGetUserInfo(idToken);
            default -> throw new InvalidParameterException("unsupported token provider");
        };

        var accessToken = jwtUtilsService.generateToken(
                new CustomUserDetails(new UserInfo(userInfo.id(), userInfo.name(), userInfo.email(), userInfo.userRole())),
                audience
        );
        return new TokenSuccessResponse(
                accessToken,
                TokenType.Bearer, Scope.user, validity, issuer,
                jwtUtilsService.generateRefreshToken(accessToken)
        );
    }

    public TokenResponse exchangeAccessTokenUsingRefreshToken(
            String refreshToken
    ) {

        jwtUtilsService.validateRefreshToken(refreshToken);

        var accessToken = jwtUtilsService.generateToken(refreshToken);
        return new TokenSuccessResponse(
                accessToken,
                TokenType.Bearer, Scope.user, validity, issuer,
                jwtUtilsService.generateRefreshToken(accessToken)
        );
    }

    public UserInfoResponse validateToken(String token, String sub, String aud) {

        var email = jwtUtilsService.validateToken(token, sub, aud);

        if (!patternMatches(email)) {
            email += "@home-stack.com";
        }

        User user = userRepository.getUserByEmail(email);

        if (user == null) {
            throw new UserNotAuthorizedException(sub + " is not authorized");
        }

        return new UserInfoResponse(
                user.getId().toString(),
                user.getFullName(),
                email,
                user.getRoles().stream().findAny().get().getName()
        );
    }

    private boolean patternMatches(String emailAddress) {
        String EMAIL_REGEX = "^(?=.{1,64}@)[A-Za-z0-9_-]+(\\.[A-Za-z0-9_-]+)*@"
                + "[^-][A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)*(\\.[A-Za-z]{2,})$";

        return Pattern.compile(EMAIL_REGEX)
                .matcher(emailAddress)
                .matches();
    }
}
