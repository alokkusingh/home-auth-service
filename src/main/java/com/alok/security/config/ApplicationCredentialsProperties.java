package com.alok.security.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

import java.util.List;

@ConfigurationProperties(prefix = "application")
@ConfigurationPropertiesScan
public class ApplicationCredentialsProperties {

    public List<ApplicationCredentials> credential;
    public List<ApplicationCredentials> getCredential() {
        return credential;
    }

    public void setCredential(List<ApplicationCredentials> credential) {
        this.credential = credential;
    }


    static class ApplicationCredentials {
        private String id;
        private String secret;
        private String role;
        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }

        public String getSecret() {
            return secret;
        }

        public void setSecret(String secret) {
            this.secret = secret;
        }

        public String getRole() {
            return role;
        }

        public void setRole(String role) {
            this.role = role;
        }



    }
}
