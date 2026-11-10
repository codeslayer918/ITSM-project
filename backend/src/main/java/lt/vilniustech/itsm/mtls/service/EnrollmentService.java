package lt.vilniustech.itsm.mtls.service;

import java.security.PublicKey;
import java.util.List;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import lt.vilniustech.itsm.mtls.auth.RequestInfo;
import lt.vilniustech.itsm.mtls.config.AppProperties;
import lt.vilniustech.itsm.mtls.domain.Account;
import lt.vilniustech.itsm.mtls.domain.IssuedCertificate;
import lt.vilniustech.itsm.mtls.domain.OneTimeToken;
import lt.vilniustech.itsm.mtls.pki.CsrValidator;
import lt.vilniustech.itsm.mtls.web.ApiException;
import lt.vilniustech.itsm.mtls.web.dto.Dtos;

/**
 * First enrolment: the administrator creates the account and an invitation token (24 h,
 * single use). The user generates a key pair locally, sends a CSR with the token and gets
 * the certificate plus 10 backup codes. The server never sees the private key.
 */
@Service
public class EnrollmentService {

    private final TokenService tokens;
    private final CsrValidator csrValidator;
    private final CertificateService certificates;
    private final BackupCodeService backupCodes;
    private final RateLimitGuard rateLimit;
    private final AuditService audit;
    private final AppProperties.RateLimit limits;

    public EnrollmentService(TokenService tokens, CsrValidator csrValidator, CertificateService certificates,
                             BackupCodeService backupCodes, RateLimitGuard rateLimit, AuditService audit,
                             AppProperties props) {
        this.tokens = tokens;
        this.csrValidator = csrValidator;
        this.certificates = certificates;
        this.backupCodes = backupCodes;
        this.rateLimit = rateLimit;
        this.audit = audit;
        this.limits = props.rateLimit();
    }

    @Transactional
    public Dtos.IssuedResponse enroll(Dtos.EnrollRequest request, RequestInfo info) {
        rateLimit.check("enroll-ip", info.ip(), limits.enrollPerIp(), limits.enrollWindow(), null, info);
        // Validate the CSR before consuming the token, so a malformed CSR does not burn it.
        PublicKey key = csrValidator.validateAndExtractKey(request.csr());
        Account account = tokens.consume(request.token(), OneTimeToken.Purpose.ENROLLMENT).orElse(null);
        if (account == null || !account.isActive()) {
            audit.record(AuditService.Type.ENROLLMENT_FAILED, AuditService.Outcome.FAILURE, null, info, null,
                    "invalid, expired or already used enrolment token");
            throw ApiException.unauthorized("invalid_token", "Invalid or expired enrolment token.");
        }

        CertificateService.IssuedBundle bundle = certificates.issue(account, key, request.label(),
                IssuedCertificate.IssuedVia.ENROLLMENT, info);

        List<String> codes = null;
        if (backupCodes.remaining(account) == 0) {
            codes = backupCodes.regenerate(account);
            audit.record(AuditService.Type.BACKUP_CODES_GENERATED, AuditService.Outcome.SUCCESS,
                    account.getUsername(), info, null, "at enrolment");
        }
        audit.record(AuditService.Type.ENROLLMENT_COMPLETED, AuditService.Outcome.SUCCESS, account.getUsername(),
                info, bundle.record().getSerialHex(), null);
        return new Dtos.IssuedResponse(bundle.record().getSerialHex(), bundle.record().getNotAfter(),
                bundle.record().getSubjectDn(), bundle.certificatePem(), bundle.chainPem(), codes,
                codes == null ? "Certificate issued."
                        : "Certificate issued. Store the backup codes offline: they are shown only once.");
    }
}
