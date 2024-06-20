package com.alok.security.config;

import com.alok.security.utils.RateLimiter;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.ConsumptionProbe;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.security.InvalidParameterException;
import java.util.UUID;

@Component
@Order(Ordered.LOWEST_PRECEDENCE)
public class RateLimitFilter extends OncePerRequestFilter {

    private RateLimiter rateLimiter;

    public RateLimitFilter(RateLimiter rateLimiter) {
        this.rateLimiter = rateLimiter;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        UserDetails principal = (UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        Bucket bucket = rateLimiter.resolveBucket(UUID.nameUUIDFromBytes(principal.getUsername().getBytes()).getMostSignificantBits());
        ConsumptionProbe probe = bucket.tryConsumeAndReturnRemaining(1);
        if (!probe.isConsumed()) {
            response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
            response.setIntHeader("X-Rate-Limit-Retry-After-Seconds", (int) (probe.getNanosToWaitForRefill() / 1_000_000_000));
            return;
        }

        response.setIntHeader("X-Rate-Limit-Remaining", (int) probe.getRemainingTokens());

        filterChain.doFilter(request,response);
    }
}
