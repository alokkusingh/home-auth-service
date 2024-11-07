package com.alok.security.utils.ratelimit.factory;

import com.alok.security.utils.ratelimit.enums.BucketFactoryType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.util.Objects;

public class BucketFactoryBuilder {

    private final Logger log = LoggerFactory.getLogger(BucketFactoryBuilder.class);

    private BucketFactoryType type;
    private DataSource dataSource;

    private boolean intialized;


    public synchronized AbstractBucketFactory build() {
        if (intialized) {
            throw new AssertionError("Rate Limit Bucket already created");
        }

        intialized = true;

        return switch (type) {
            case null -> InMemoryBucketFactory.getInstance();
            case IN_MEMEORY -> InMemoryBucketFactory.getInstance();
            case POSTGRESQL -> {
                if (Objects.isNull(dataSource)) {
                    throw new AssertionError("DataSource object must be provided for POSTGRESQL Factory Type");
                }
                yield PostgresqlBucketFactory.getInstance(dataSource);
            }
        };
    }

    public BucketFactoryBuilder setType(BucketFactoryType type) {
        this.type = type;
        return this;
    }

    public BucketFactoryBuilder setDataSource(DataSource dataSource) {
        this.dataSource = dataSource;
        return this;
    }
}