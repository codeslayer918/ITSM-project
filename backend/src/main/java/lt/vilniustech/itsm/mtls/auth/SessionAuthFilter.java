package lt.vilniustech.itsm.mtls.auth;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import lt.vilniustech.itsm.mtls.config.AppProperties;
import lt.vilniustech.itsm.mtls.domain.Account;
import lt.vilniustech.itsm.mtls.domain.IssuedCertificate;
import lt.vilniustech.itsm.mtls.repo.AccountRepository;
import lt.vilniustech.itsm.mtls.repo.IssuedCertificateRepository;
import lt.vilniustech.itsm.mtls.service.AuditService;
import lt.vilniustech.itsm.mtls.web.ApiException;

/**
 * Protects /api/me/**, /api/admin/** and /api/logout. On every request:
 *  1. the TLS client certificate is re-validated (ClientCertificateExtractor),
 *  2. a session created by POST /api/login must exist,
 *  3. the session is bound to the certificate that created it: a stolen session cookie
 *     is useless without the private key of that certificate,
 *  4. the certificate must still be ACTIVE in the database: this is the application-level
 *     revocation list, effective immediately (before nginx reloads the CRL),
 *  5. the account must be active and its session epoch unchanged (reset / revocation
 *     invalidates every existing session),
 *  6. the absolute session lifetime is enforced (idle timeout is handled by the container),
 *  7. /api/admin/** additionally requires role ADMIN *and* a certificate with OU=admins.
 */
@Component
@Order(3)
public class SessionAuthFilter extends OncePerRequestFilter {

    private final ClientCertificateExtractor extractor;
    private final IssuedCertificateRepository certificates;
    private final AccountRepository accounts;
    private final AuditService audit;
    private final Duration absoluteTimeout;

    public SessionAuthFilter(ClientCertificateExtractor extractor, IssuedCertificateRepository certificates,
                             AccountRepository accounts, AuditService audit, AppProperties props) {
        this.extractor = extractor;
        this.certificates = certificates;
        this.accounts = accounts;
        this.audit = audit;
        this.absoluteTimeout = props.sessionAbsoluteTimeout();
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return !(path.startsWith("/api/me") || path.startsWith("/api/admin") || path.equals("/api/logout"));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        try {
            AuthContext ctx = authenticate(request);
            request.setAttribute(AuthContext.REQUEST_ATTRIBUTE, ctx);
        } catch (ApiException e) {
            FilterErrors.write(response, e);
            return;
        }
        chain.doFilter(request, response);
    }

    private AuthContext authenticate(HttpServletRequest request) {
        RequestInfo info = RequestInfo.of(request);
        ClientCertificate cc = extractor.extract(request);

        HttpSession session = request.getSession(false);
        if (session == null || session.getAttribute(SessionKeys.ACCOUNT_ID) == null) {
            throw ApiException.unauthorized("not_authenticated", "No session: POST /api/login first.");
        }
        Long accountId = (Long) session.getAttribute(SessionKeys.ACCOUNT_ID);
        String boundFingerprint = (String) session.getAttribute(SessionKeys.CERT_FINGERPRINT);
        Integer epoch = (Integer) session.getAttribute(SessionKeys.EPOCH);
        Instant loginAt = (Instant) session.getAttribute(SessionKeys.LOGIN_AT);

        if (!cc.fingerprintSha256().equals(boundFingerprint)) {
            session.invalidate();
            audit.record(AuditService.Type.SESSION_REJECTED, AuditService.Outcome.DENIED, cc.commonName(), info,
                    cc.serialHex(), "session cookie presented with a different client certificate");
            throw ApiException.unauthorized("session_certificate_mismatch",
                    "This session belongs to another certificate.");
        }
        if (loginAt == null || Instant.now().isAfter(loginAt.plus(absoluteTimeout))) {
            session.invalidate();
            throw ApiException.unauthorized("session_expired", "Session expired, log in again.");
        }

        Optional<IssuedCertificate> cert = certificates.findByFingerprintSha256(cc.fingerprintSha256());
        if (cert.isEmpty() || !cert.get().isActive()) {
            session.invalidate();
            audit.record(AuditService.Type.SESSION_REJECTED, AuditService.Outcome.DENIED, cc.commonName(), info,
                    cc.serialHex(), "certificate revoked (application-level revocation list)");
            throw ApiException.forbidden("certificate_revoked", "This certificate has been revoked.");
        }
        Account account = accounts.findById(accountId).orElse(null);
        if (account == null || !account.getId().equals(cert.get().getAccount().getId()) || !account.isActive()
                || epoch == null || account.getSessionEpoch() != epoch) {
            session.invalidate();
            audit.record(AuditService.Type.SESSION_REJECTED, AuditService.Outcome.DENIED, cc.commonName(), info,
                    cc.serialHex(), "session invalidated (reset, revocation or disabled account)");
            throw ApiException.unauthorized("session_revoked", "Session no longer valid, log in again.");
        }

        boolean adminCertificate = Account.ADMIN_GROUP.equals(cc.organizationalUnit());
        if (request.getRequestURI().startsWith("/api/admin") && !(account.isAdmin() && adminCertificate)) {
            audit.record(AuditService.Type.ADMIN_ACCESS_DENIED, AuditService.Outcome.DENIED, account.getUsername(),
                    info, cc.serialHex(), request.getMethod() + " " + request.getRequestURI());
            throw ApiException.forbidden("admin_required", "An administrator certificate (OU=admins) is required.");
        }
        return new AuthContext(account.getId(), account.getUsername(), account.isAdmin() && adminCertificate,
                cc.serialHex(), cc.fingerprintSha256(), info);
    }
}
