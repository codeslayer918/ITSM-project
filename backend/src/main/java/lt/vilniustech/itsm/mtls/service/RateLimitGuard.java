package lt.vilniustech.itsm.mtls.service;

import java.time.Duration;

import org.springframework.stereotype.Component;

import lt.vilniustech.itsm.mtls.auth.RequestInfo;
import lt.vilniustech.itsm.mtls.web.ApiException;

/** Applies a rate limit and records the event in the audit log when it triggers. */
@Component
public class RateLimitGuard {

    private final RateLimiter limiter;
    private final AuditService audit;

    public RateLimitGuard(RateLimiter limiter, AuditService audit) {
        this.limiter = limiter;
        this.audit = audit;
    }

    public void check(String scope, String key, int limit, Duration window, String username, RequestInfo info) {
        try {
            limiter.consume(scope + ":" + key.toLowerCase(), limit, window);
        } catch (ApiException e) {
            audit.record(AuditService.Type.RATE_LIMITED, AuditService.Outcome.DENIED, username, info, null,
                    "scope=" + scope);
            throw e;
        }
    }
}
