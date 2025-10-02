package com.alok.security.token.service;

import com.alok.home.commons.dto.exception.InvalidTokenException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.DefaultClaims;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtUtilsService {


    private final String applicationId;
    private final String secret;
    private final Integer accessTokenValidity;
    private final Integer refreshTokenValidity; // 7 days

    private final String DEFAULT_SUBJECT = "home-stack";

    public JwtUtilsService(
            @Value("${application.id}") String applicationId,
            @Value("${application.security.jwt.secret}") String secret,
            @Value("${application.security.jwt.access-token.validity}") Integer accessTokenValidity,
            @Value("${application.security.jwt.refresh-token.validity}") Integer refreshTokenValidity
    ) {
        this.applicationId = applicationId;
        this.secret = secret;
        this.accessTokenValidity = accessTokenValidity;
        this.refreshTokenValidity = refreshTokenValidity;
    }

    //retrieve username from jwt token
    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    //retrieve expiration date from jwt token
    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }
    //for retrieving any information from token we will need the secret key
    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
    }

    //check if the token has expired
    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    //generate token for user
    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("auth", userDetails.getAuthorities().stream().findAny().get().getAuthority());
        return doGenerateToken(claims, userDetails.getUsername());
    }

    //generate token for user
    public String generateToken(UserDetails userDetails, String audience) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("auth", userDetails.getAuthorities().stream().findAny().get().getAuthority());
        return doGenerateToken(claims, userDetails.getUsername(), audience);
    }

    public String generateToken(String subject, String scope) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("auth", scope);
        return doGenerateToken(claims, subject);
    }

    public String generateToken(String subject, String scope, String audience) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("auth", scope);
        return doGenerateToken(claims, subject, audience);
    }

    public String generateToken(String refreshToken) {
        Claims claims = getAllClaimsFromToken(refreshToken);
        Claims newClaims = new DefaultClaims();
        newClaims.put("auth", claims.get("auth"));
        return this.doGenerateToken(newClaims, claims.getSubject(), claims.get("for", String.class));
    }

    public String generateRefreshToken(String accessToken) {
        Claims claims = getAllClaimsFromToken(accessToken);
        return doGenerateRefreshToken(claims, claims.getSubject(), claims.getAudience());
    }

    //while creating the token -
    //1. Define  claims of the token, like Issuer, Expiration, Subject, and the ID
    //2. Sign the JWT using the HS512 algorithm and secret key.
    //3. According to JWS Compact Serialization(https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-3.1)
    //   compaction of the JWT to a URL-safe string
    private String doGenerateToken(Map<String, Object> claims, String subject) {

        return doGenerateToken(claims, subject, DEFAULT_SUBJECT);
    }

    private String doGenerateToken(Map<String, Object> claims, String subject, String audience) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuer(applicationId)
                .setAudience(audience)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + accessTokenValidity * 1000))
                .signWith(SignatureAlgorithm.HS256, secret)
                .compact();
    }

    private String doGenerateRefreshToken(Map<String, Object> claims, String subject, String audience) {

        claims.put("for", audience);
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuer(applicationId)
                .setAudience(applicationId) // refresh token is only for the issuer, this will prevent using as access token
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + refreshTokenValidity * 1000))
                .signWith(SignatureAlgorithm.HS256, secret)
                .compact();
    }

    //validate token
    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = getUsernameFromToken(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    public String validateToken(String token, String subject, String audience) {
        try {
            if (Boolean.TRUE.equals(isTokenExpired(token))) {
                throw new InvalidTokenException("token expired");
            }
        } catch (ExpiredJwtException eje) {
            throw new InvalidTokenException(eje.getMessage());
        }

        Claims claims = getAllClaimsFromToken(token);

        if (!claims.getIssuer().equals(applicationId)) {
            throw new InvalidTokenException("untrusted token issuer");
        }

        if (subject != null && !claims.getSubject().equals(subject)) {
            throw new InvalidTokenException("token not provided for the subject");
        }

        if (audience == null || audience.isBlank()) {
            if (!claims.getAudience().equals(DEFAULT_SUBJECT)) {
                throw new InvalidTokenException("token not provided for the audience");
            }
        } else {
            if (!claims.getAudience().equals(audience)) {
                throw new InvalidTokenException("token not provided for the audience");
            }
        }

        return claims.getSubject();
    }

    public void validateRefreshToken(String token) {
        try {
            if (Boolean.TRUE.equals(isTokenExpired(token))) {
                throw new InvalidTokenException("token expired");
            }
        } catch (ExpiredJwtException eje) {
            throw new InvalidTokenException(eje.getMessage());
        }

        Claims claims = getAllClaimsFromToken(token);

        if (!claims.getIssuer().equals(applicationId)) {
            throw new InvalidTokenException("untrusted token issuer");
        }

        if (!claims.getAudience().equals(applicationId)) {
            throw new InvalidTokenException("invalid refresh token audience");
        }
    }
}
