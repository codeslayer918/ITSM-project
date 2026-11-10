package lt.vilniustech.itsm.mtls.service;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import lt.vilniustech.itsm.mtls.web.ApiException;

/**
 * Sliding-window rate limiter (in memory, single instance). Every attempt counts, successful
 * or not, so an attacker cannot reset the counter by mixing in valid requests.
 * Used on the public enrolment and recovery endpoints, which are the only ones reachable
 * without a client certificate. nginx applies a coarser per-IP limit in front of it.
 */
@Component
public class RateLimiter {

    private final Map<String, Deque<Long>> windows = new ConcurrentHashMap<>();
    private final Clock clock;

    public RateLimiter() {
        this(Clock.systemUTC());
    }

    RateLimiter(Clock clock) {
        this.clock = clock;
    }

    /** Records an attempt for {@code key}; throws 429 if more than {@code limit} attempts in {@code window}. */
    public void consume(String key, int limit, Duration window) {
        long now = clock.millis();
        long windowStart = now - window.toMillis();
        Deque<Long> attempts = windows.computeIfAbsent(key, k -> new ArrayDeque<>());
        synchronized (attempts) {
            while (!attempts.isEmpty() && attempts.peekFirst() <= windowStart) {
                attempts.pollFirst();
            }
            if (attempts.size() >= limit) {
                long retryAfterMs = attempts.peekFirst() + window.toMillis() - now;
                throw new ApiException(HttpStatus.TOO_MANY_REQUESTS, "rate_limited",
                        "Too many attempts, try again later.", Math.max(1, retryAfterMs / 1000));
            }
            attempts.addLast(now);
        }
    }

    @Scheduled(fixedDelayString = "PT5M")
    void evictEmptyWindows() {
        long cutoff = clock.millis() - Duration.ofHours(2).toMillis();
        windows.entrySet().removeIf(e -> {
            synchronized (e.getValue()) {
                return e.getValue().isEmpty() || e.getValue().peekLast() < cutoff;
            }
        });
    }
}
