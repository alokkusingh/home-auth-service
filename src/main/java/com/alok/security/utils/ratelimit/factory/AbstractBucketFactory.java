package com.alok.security.utils.ratelimit.factory;

import io.github.bucket4j.Bucket;

public sealed abstract class AbstractBucketFactory permits InMemoryBucketFactory, PostgresqlBucketFactory {

    public abstract Bucket resolveBucket(String id);

    public static BucketFactoryBuilder builder() {
        return new BucketFactoryBuilder();
    }
}
