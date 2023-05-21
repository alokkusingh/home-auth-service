package com.alok.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@ConfigurationPropertiesScan({"com.alok.security.config"})
@SpringBootApplication
public class HomeAuthoriserApplication {

	public static void main(String[] args) {
		SpringApplication.run(HomeAuthoriserApplication.class, args);
	}

}
