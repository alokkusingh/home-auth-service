package com.alok.security.token.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import com.alok.home.commons.dto.EmailRequest;

@Service
public class EmailService {

    private final RestTemplate emailRestTemplate;

    private final String emailUrl;

    public EmailService(
            RestTemplate emailRestTemplate,
            @Value("${email.url}") String emailUrl
    ) {
        this.emailRestTemplate = emailRestTemplate;
        this.emailUrl = emailUrl;
    }

    @Async
    public void sendEmail(
            String subject, String body
    ) {
        HttpEntity<EmailRequest> request = new HttpEntity<>(
                new EmailRequest(
                        "alok.ku.singh@gmail.com",
                        subject,
                        body
                )
        );

        emailRestTemplate.postForEntity(emailUrl, request, String.class);
    }
}
