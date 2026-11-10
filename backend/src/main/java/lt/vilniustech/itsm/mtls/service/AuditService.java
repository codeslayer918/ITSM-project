package lt.vilniustech.itsm.mtls.service;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import lt.vilniustech.itsm.mtls.auth.RequestInfo;
import lt.vilniustech.itsm.mtls.domain.AuditEvent;
import lt.vilniustech.itsm.mtls.repo.AuditEventRepository;

/**
 * Security audit trail (Repudiation in STRIDE). Every event goes to the database (shown on
 * the admin page) and to the "AUDIT" logger (stdout, ready to be shipped to a SIEM).
 * Never pass secrets here: no backup codes, tokens, session ids or private keys.
 */
@Service
public class AuditService {

    public enum Type {
        LOGIN_SUCCESS, LOGIN_FAILURE, LOGOUT, SESSION_REJECTED,
        ENROLLMENT_TOKEN_CREATED, ENROLLMENT_COMPLETED, ENROLLMENT_FAILED,
        CERTIFICATE_ISSUED, CERTIFICATE_REVOKED, USER_REVOKED, GROUP_REVOKED, USER_ENABLED,
        BACKUP_CODES_GENERATED, BACKUP_CODE_USED,
        RECOVERY_LINK_REQUESTED, RECOVERY_COMPLETED, RECOVERY_FAILED,
        RATE_LIMITED, ADMIN_ACCESS_DENIED, CRL_PUBLISHED
    }

    public enum Outcome { SUCCESS, FAILURE, DENIED }

    private static final Logger audit = LoggerFactory.getLogger("AUDIT");

    private final AuditEventRepository repository;

    public AuditService(AuditEventRepository repository) {
        this.repository = repository;
    }

    /** Own transaction: a failed operation that rolls back is still recorded. */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void record(Type type, Outcome outcome, String username, RequestInfo info, String certSerial, String details) {
        String ip = info == null ? null : info.ip();
        String ua = info == null ? null : info.userAgent();
        repository.save(new AuditEvent(type.name(), outcome.name(), truncate(username, 64), ip, ua, certSerial,
                truncate(details, 1024)));
        audit.info("event={} outcome={} user={} ip={} serial={} details=\"{}\"",
                type, outcome, sanitize(username), ip, certSerial, sanitize(details));
    }

    public List<AuditEvent> latest() {
        return repository.findTop200ByOrderByOccurredAtDesc();
    }

    private static String truncate(String value, int max) {
        return value == null || value.length() <= max ? value : value.substring(0, max);
    }

    /** Prevents log injection (CR/LF and quotes in user-controlled values). */
    private static String sanitize(String value) {
        return value == null ? null : value.replaceAll("[\\r\\n\"]", "_");
    }
}
