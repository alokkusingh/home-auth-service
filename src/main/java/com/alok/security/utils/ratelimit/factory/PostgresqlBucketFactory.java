package com.alok.security.utils.ratelimit.factory;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.BucketConfiguration;
import io.github.bucket4j.Refill;
import io.github.bucket4j.distributed.jdbc.BucketTableSettings;
import io.github.bucket4j.distributed.jdbc.SQLProxyConfigurationBuilder;
import io.github.bucket4j.distributed.proxy.ClientSideConfig;
import io.github.bucket4j.distributed.proxy.ProxyManager;
import io.github.bucket4j.mysql.MySQLSelectForUpdateBasedProxyManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.time.Duration;
import java.util.UUID;

public class PostgresqlBucketFactory extends AbstractBucketFactory {

    private final Logger log = LoggerFactory.getLogger(PostgresqlBucketFactory.class);
    private static volatile PostgresqlBucketFactory instance;

    private static final Bandwidth limit = Bandwidth.classic(3, Refill.greedy(3, Duration.ofMinutes(1)));

    private DataSource dataSource;
    private ProxyManager proxyManager;

    private PostgresqlBucketFactory(DataSource dataSource) {
        this.dataSource = dataSource;
        this.proxyManager = new MySQLSelectForUpdateBasedProxyManager(
                SQLProxyConfigurationBuilder.builder()
                        .withClientSideConfig(ClientSideConfig.getDefault())
                        .withTableSettings(BucketTableSettings.getDefault())
                        .build(dataSource)
        );
    }

    protected static PostgresqlBucketFactory getInstance(final DataSource dataSource) {
        if (instance == null) {
            synchronized (PostgresqlBucketFactory.class) {
                if (instance == null) {
                    instance = new PostgresqlBucketFactory(dataSource);
                }
            }
        }

        return instance;
    }

    public Bucket resolveBucket(String id) {

        return proxyManager.builder().build(
                UUID.nameUUIDFromBytes(id.getBytes()).getMostSignificantBits(),
                BucketConfiguration.builder()
                .addLimit(limit)
                .build()
        );
    }
}
