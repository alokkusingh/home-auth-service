package com.alok.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.scheduling.annotation.EnableAsync;

@EnableAsync
@ConfigurationPropertiesScan({
		"com.alok.security.config",
		"com.alok.home.commons.security.properties"
})
@SpringBootApplication(
		scanBasePackages = {
				"com.alok.security"
		}
)
public class HomeAuthoriserApplication {

	public static void main(String[] args) {
		SpringApplication.run(HomeAuthoriserApplication.class, args);
	}

}
