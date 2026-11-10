package lt.vilniustech.itsm.mtls.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

import lt.vilniustech.itsm.mtls.web.ApiException;

class RateLimiterTest {

    @Test
    void blocksAfterLimitAndRecoversAfterWindow() {
        AtomicLong now = new AtomicLong(1_000_000);
        Clock clock = new Clock() {
            @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
            @Override public Clock withZone(java.time.ZoneId zone) { return this; }
            @Override public Instant instant() { return Instant.ofEpochMilli(now.get()); }
        };
        RateLimiter limiter = new RateLimiter(clock);
        Duration window = Duration.ofMinutes(15);

        for (int i = 0; i < 5; i++) {
            limiter.consume("ip:1.2.3.4", 5, window);
        }
        assertThatThrownBy(() -> limiter.consume("ip:1.2.3.4", 5, window))
                .isInstanceOfSatisfying(ApiException.class, e -> {
                    assertThat(e.getStatus()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
                    assertThat(e.getRetryAfterSeconds()).isPositive();
                });
        limiter.consume("ip:5.6.7.8", 5, window); // other keys are independent

        now.addAndGet(window.toMillis() + 1);
        limiter.consume("ip:1.2.3.4", 5, window);
    }
}
