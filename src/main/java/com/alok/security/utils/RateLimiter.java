package com.alok.security.utils;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.BucketConfiguration;
import io.github.bucket4j.Refill;
import io.github.bucket4j.distributed.proxy.ProxyManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
public class RateLimiter {


    private ProxyManager proxyManager;

    public RateLimiter(ProxyManager proxyManager) {
        this.proxyManager = proxyManager;
    }


    public Bucket resolveBucket(long key) {

        return proxyManager.builder().build(
                key,
                BucketConfiguration.builder()
                .addLimit(Bandwidth.classic(3, Refill.greedy(3, Duration.ofMinutes(1))))
                .build()
        );
    }
}
