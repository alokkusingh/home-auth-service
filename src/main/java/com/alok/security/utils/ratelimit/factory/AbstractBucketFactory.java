package com.alok.security.utils.ratelimit.factory;

import io.github.bucket4j.Bucket;

public abstract class AbstractBucketFactory {

    public abstract Bucket resolveBucket(String id);

    public static BucketFactoryBuilder builder() {
        return new BucketFactoryBuilder();
    }
}
