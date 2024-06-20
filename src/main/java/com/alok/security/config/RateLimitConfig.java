package com.alok.security.config;

import io.github.bucket4j.distributed.jdbc.BucketTableSettings;
import io.github.bucket4j.distributed.jdbc.SQLProxyConfigurationBuilder;
import io.github.bucket4j.distributed.proxy.ClientSideConfig;
import io.github.bucket4j.distributed.proxy.ProxyManager;
import io.github.bucket4j.mysql.MySQLSelectForUpdateBasedProxyManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.sql.DataSource;

@Configuration
public class RateLimitConfig {


    @Autowired
    DataSource dataSource;

    @Bean
    ProxyManager<String> proxyManager() {
        return new MySQLSelectForUpdateBasedProxyManager(
                SQLProxyConfigurationBuilder.builder()
                        .withClientSideConfig(ClientSideConfig.getDefault())
                        .withTableSettings(BucketTableSettings.getDefault())
                .build(dataSource)
        );
    }
}
