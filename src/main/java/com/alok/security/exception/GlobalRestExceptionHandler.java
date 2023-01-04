package com.alok.security.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import javax.naming.AuthenticationException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.InvalidParameterException;
import java.time.ZonedDateTime;

@RestControllerAdvice
public class GlobalRestExceptionHandler extends ResponseEntityExceptionHandler {

    @ExceptionHandler(AuthenticationException.class)
    ProblemDetail handleAuthenticationException(AuthenticationException e) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.FORBIDDEN, e.getMessage());
        problemDetail.setTitle("User not authorized");
        problemDetail.setType(URI.create("home-api/errors/forbidden"));
        problemDetail.setProperty("errorCategory", "Unauthorized");
        problemDetail.setProperty("timestamp", ZonedDateTime.now());
        e.printStackTrace();
        return problemDetail;
    }

    @ExceptionHandler(GeneralSecurityException.class)
    ProblemDetail handleGeneralSecurityException(GeneralSecurityException e) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.FORBIDDEN, e.getMessage());
        problemDetail.setTitle("Invalid Token");
        problemDetail.setType(URI.create("home-api/errors/forbidden"));
        problemDetail.setProperty("errorCategory", "InvalidToken");
        problemDetail.setProperty("timestamp", ZonedDateTime.now());
        e.printStackTrace();
        return problemDetail;
    }

    @ExceptionHandler(InvalidParameterException.class)
    ProblemDetail handleInvalidParameterException(InvalidParameterException e) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, e.getMessage());
        problemDetail.setTitle("Bad Request");
        problemDetail.setType(URI.create("home-api/errors/bad-request"));
        problemDetail.setProperty("errorCategory", "BadRequest");
        problemDetail.setProperty("timestamp", ZonedDateTime.now());
        e.printStackTrace();
        return problemDetail;
    }
}
