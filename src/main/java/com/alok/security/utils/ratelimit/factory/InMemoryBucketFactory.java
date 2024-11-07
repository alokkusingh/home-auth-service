package com.alok.security.utils.ratelimit.factory;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public final class InMemoryBucketFactory extends AbstractBucketFactory {

    private final Logger log = LoggerFactory.getLogger(InMemoryBucketFactory.class);
    private static volatile InMemoryBucketFactory instance;

    private final Map<String, Bucket> cache = new ConcurrentHashMap<>();
    private static final Bandwidth limit = Bandwidth.classic(3, Refill.greedy(3, Duration.ofMinutes(1)));

    private InMemoryBucketFactory() {
    }

    protected static InMemoryBucketFactory getInstance() {
        if (instance == null) {
            synchronized (InMemoryBucketFactory.class) {
                if (instance == null) {
                    instance = new InMemoryBucketFactory();
                }
            }
        }

        return instance;
    }

    public Bucket resolveBucket(String id) {
        return cache.computeIfAbsent(id, this::newBucket);
    }

    private Bucket newBucket(String apiKey) {
        return Bucket.builder()
                .addLimit(limit)
                .build();
    }
}
