package com.alok.security.token.service;

import com.alok.home.commons.exception.InvalidTokenException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtUtilsService {

    @Value("${application.id}")
    private String applicationId;
    @Value("${application.security.jwt.secret}")
    private String secret;

    @Value("${application.security.jwt.validity}")
    private Integer validity;

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
    //for retrieveing any information from token we will need the secret key
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
        return doGenerateToken(claims, userDetails.getUsername());
    }

    public String generateToken(String subject, String scope) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("auth", scope);
        return doGenerateToken(claims, subject);
    }

    //while creating the token -
    //1. Define  claims of the token, like Issuer, Expiration, Subject, and the ID
    //2. Sign the JWT using the HS512 algorithm and secret key.
    //3. According to JWS Compact Serialization(https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-3.1)
    //   compaction of the JWT to a URL-safe string
    private String doGenerateToken(Map<String, Object> claims, String subject) {

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuer("home-stack-auth")
                .setAudience("home-stack-api")
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + validity * 1000))
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

        if (!claims.getSubject().equals(subject)) {
            throw new InvalidTokenException("token not provided for the subject");
        }

        if (!claims.getAudience().equals(audience)) {
            throw new InvalidTokenException("token not provided for the audience");
        }

        return (String)claims.get("auth");
    }
}
