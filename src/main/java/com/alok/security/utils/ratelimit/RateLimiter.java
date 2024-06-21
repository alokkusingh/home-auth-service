package com.alok.security.utils.ratelimit;

import com.alok.security.utils.ratelimit.factory.AbstractBucketFactory;
import com.alok.security.utils.ratelimit.factory.BucketFactoryBuilder;
import com.alok.security.utils.ratelimit.enums.BucketFactoryType;
import io.github.bucket4j.Bucket;
import org.springframework.stereotype.Service;

import javax.sql.DataSource;


@Service
public class RateLimiter {

    private DataSource dataSource;

    private AbstractBucketFactory bucketFactory;
    public RateLimiter(DataSource dataSource) {
        this.dataSource = dataSource;
//        bucketFactory = AbstractBucketFactory.builder()
//                .setType(BucketFactoryType.IN_MEMEORY)
//                .build();
        bucketFactory = AbstractBucketFactory.builder()
                .setType(BucketFactoryType.POSTGRESQL)
                .setDataSource(this.dataSource)
                .build();
    }

    public Bucket resolveBucket(String id) {
        return bucketFactory.resolveBucket(id);
    }
}
