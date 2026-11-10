package lt.vilniustech.itsm.mtls.web;

import java.time.Instant;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import lt.vilniustech.itsm.mtls.auth.AuthContext;
import lt.vilniustech.itsm.mtls.auth.ClientCertificate;
import lt.vilniustech.itsm.mtls.auth.ClientCertificateExtractor;
import lt.vilniustech.itsm.mtls.auth.RequestInfo;
import lt.vilniustech.itsm.mtls.auth.SessionKeys;
import lt.vilniustech.itsm.mtls.domain.Account;
import lt.vilniustech.itsm.mtls.domain.IssuedCertificate;
import lt.vilniustech.itsm.mtls.repo.IssuedCertificateRepository;
import lt.vilniustech.itsm.mtls.service.AuditService;

/**
 * Login = the TLS client certificate verified by nginx, mapped to an account through its
 * SHA-256 fingerprint. A successful login always creates a *new* session id (session
 * fixation defence) and binds the session to the certificate.
 */
@RestController
public class LoginController {

    private final ClientCertificateExtractor extractor;
    private final IssuedCertificateRepository certificates;
    private final AuditService audit;

    public LoginController(ClientCertificateExtractor extractor, IssuedCertificateRepository certificates,
                           AuditService audit) {
        this.extractor = extractor;
        this.certificates = certificates;
        this.audit = audit;
    }

    @PostMapping("/api/login")
    @Transactional(readOnly = true)
    public Map<String, Object> login(HttpServletRequest request) {
        RequestInfo info = RequestInfo.of(request);
        ClientCertificate cc;
        try {
            cc = extractor.extract(request);
        } catch (ApiException e) {
            audit.record(AuditService.Type.LOGIN_FAILURE, AuditService.Outcome.DENIED, null, info, null, e.getCode());
            throw e;
        }

        IssuedCertificate cert = certificates.findByFingerprintSha256(cc.fingerprintSha256()).orElse(null);
        if (cert == null) {
            audit.record(AuditService.Type.LOGIN_FAILURE, AuditService.Outcome.DENIED, cc.commonName(), info,
                    cc.serialHex(), "certificate not registered to any account");
            throw ApiException.unauthorized("unknown_certificate", "This certificate is not registered.");
        }
        if (!cert.isActive()) {
            audit.record(AuditService.Type.LOGIN_FAILURE, AuditService.Outcome.DENIED, cc.commonName(), info,
                    cc.serialHex(), "certificate revoked (application-level revocation list)");
            throw ApiException.forbidden("certificate_revoked", "This certificate has been revoked.");
        }
        Account account = cert.getAccount();
        if (!account.isActive()) {
            audit.record(AuditService.Type.LOGIN_FAILURE, AuditService.Outcome.DENIED, account.getUsername(), info,
                    cc.serialHex(), "account disabled");
            throw ApiException.forbidden("account_disabled", "This account is disabled.");
        }

        // Session fixation defence: discard any session presented by the client, issue a new id.
        HttpSession previous = request.getSession(false);
        if (previous != null) {
            previous.invalidate();
        }
        HttpSession session = request.getSession(true);
        Instant now = Instant.now();
        session.setAttribute(SessionKeys.ACCOUNT_ID, account.getId());
        session.setAttribute(SessionKeys.CERT_FINGERPRINT, cc.fingerprintSha256());
        session.setAttribute(SessionKeys.EPOCH, account.getSessionEpoch());
        session.setAttribute(SessionKeys.LOGIN_AT, now);

        boolean adminSession = account.isAdmin() && Account.ADMIN_GROUP.equals(cc.organizationalUnit());
        audit.record(AuditService.Type.LOGIN_SUCCESS, AuditService.Outcome.SUCCESS, account.getUsername(), info,
                cc.serialHex(), "admin=" + adminSession);
        return Map.of("username", account.getUsername(), "group", account.getGroup(), "admin", adminSession,
                "certificateSerial", cc.serialHex(), "message", "Logged in with client certificate " + cc.subjectDn());
    }

    @PostMapping("/api/logout")
    public Map<String, String> logout(HttpServletRequest request, HttpServletResponse response) {
        AuthContext auth = AuthContext.require(request);
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        response.addHeader("Set-Cookie", "__Host-SID=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict");
        audit.record(AuditService.Type.LOGOUT, AuditService.Outcome.SUCCESS, auth.username(), auth.requestInfo(),
                auth.certSerial(), null);
        return Map.of("message", "Logged out.");
    }
}
