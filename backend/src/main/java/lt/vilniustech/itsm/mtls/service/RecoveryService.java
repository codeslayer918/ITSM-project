package lt.vilniustech.itsm.mtls.service;

import java.security.PublicKey;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import lt.vilniustech.itsm.mtls.auth.RequestInfo;
import lt.vilniustech.itsm.mtls.config.AppProperties;
import lt.vilniustech.itsm.mtls.domain.Account;
import lt.vilniustech.itsm.mtls.domain.IssuedCertificate;
import lt.vilniustech.itsm.mtls.domain.OneTimeToken;
import lt.vilniustech.itsm.mtls.pki.CsrValidator;
import lt.vilniustech.itsm.mtls.repo.AccountRepository;
import lt.vilniustech.itsm.mtls.web.ApiException;
import lt.vilniustech.itsm.mtls.web.dto.Dtos;

/**
 * Certificate reset for a user who lost every certificate. Two ways to prove identity:
 *  a) username + one backup code (Argon2id, single use);
 *  b) a magic link sent to the registered e-mail address (single use, 15 minutes).
 *     Disabled for administrators: an e-mail account takeover must not give admin rights.
 *
 * In both cases the user sends a CSR (the key is generated on the user's machine), then:
 * every previously active certificate is revoked, every session is invalidated,
 * the CRL is regenerated and the user is notified by e-mail.
 * Both endpoints are rate limited per IP and per account, and answer with the same
 * generic error whether the account exists or not.
 */
@Service
public class RecoveryService {

    private static final String GENERIC_LINK_MESSAGE =
            "If an account exists for this address, a recovery link has been sent.";

    private final AccountRepository accounts;
    private final BackupCodeService backupCodes;
    private final TokenService tokens;
    private final CsrValidator csrValidator;
    private final CertificateService certificates;
    private final NotificationService notifications;
    private final RateLimitGuard rateLimit;
    private final AuditService audit;
    private final AppProperties props;
    private final MagicLinkWorker magicLinkWorker;

    public RecoveryService(AccountRepository accounts, BackupCodeService backupCodes, TokenService tokens,
                           CsrValidator csrValidator, CertificateService certificates,
                           NotificationService notifications, RateLimitGuard rateLimit, AuditService audit,
                           AppProperties props, MagicLinkWorker magicLinkWorker) {
        this.accounts = accounts;
        this.backupCodes = backupCodes;
        this.tokens = tokens;
        this.csrValidator = csrValidator;
        this.certificates = certificates;
        this.notifications = notifications;
        this.rateLimit = rateLimit;
        this.audit = audit;
        this.props = props;
        this.magicLinkWorker = magicLinkWorker;
    }

    // ------------------------------------------------------------- backup code

    @Transactional
    public Dtos.IssuedResponse recoverWithBackupCode(Dtos.BackupCodeRecoveryRequest request, RequestInfo info) {
        AppProperties.RateLimit limits = props.rateLimit();
        String username = request.username().trim().toLowerCase();
        rateLimit.check("recovery-ip", info.ip(), limits.recoveryPerIp(), limits.recoveryWindow(), username, info);
        rateLimit.check("recovery-account", username, limits.recoveryPerAccount(), limits.recoveryWindow(),
                username, info);
        PublicKey key = csrValidator.validateAndExtractKey(request.csr());

        Account account = accounts.findByUsername(username).filter(Account::isActive).orElse(null);
        boolean valid = backupCodes.verifyAndConsume(account, request.backupCode());
        if (!valid) {
            audit.record(AuditService.Type.RECOVERY_FAILED, AuditService.Outcome.FAILURE, username, info, null,
                    "method=backup_code");
            throw ApiException.unauthorized("invalid_credentials", "Invalid username or backup code.");
        }
        long remaining = backupCodes.remaining(account);
        audit.record(AuditService.Type.BACKUP_CODE_USED, AuditService.Outcome.SUCCESS, username, info, null,
                "remaining=" + remaining);
        Dtos.IssuedResponse response = resetCertificates(account, key, request.label(),
                IssuedCertificate.IssuedVia.RECOVERY_BACKUP_CODE, info);
        return new Dtos.IssuedResponse(response.serial(), response.notAfter(), response.subject(),
                response.certificatePem(), response.chainPem(), null,
                response.message() + " Backup codes left: " + remaining + ".");
    }

    // -------------------------------------------------------------- magic link

    public String requestMagicLink(Dtos.MagicLinkRequest request, RequestInfo info) {
        AppProperties.RateLimit limits = props.rateLimit();
        String email = request.email().trim().toLowerCase();
        rateLimit.check("recovery-ip", info.ip(), limits.recoveryPerIp(), limits.recoveryWindow(), null, info);
        rateLimit.check("magic-link-email", email, limits.magicLinkPerEmail(), limits.magicLinkWindow(), null, info);

        // Everything that depends on the account existing happens in the background (constant timing).
        magicLinkWorker.process(email, info);
        return GENERIC_LINK_MESSAGE;
    }

    @Transactional
    public Dtos.IssuedResponse completeMagicLink(Dtos.MagicLinkCompleteRequest request, RequestInfo info) {
        AppProperties.RateLimit limits = props.rateLimit();
        rateLimit.check("recovery-ip", info.ip(), limits.recoveryPerIp(), limits.recoveryWindow(), null, info);
        PublicKey key = csrValidator.validateAndExtractKey(request.csr());
        Account account = tokens.consume(request.token(), OneTimeToken.Purpose.MAGIC_LINK)
                .filter(Account::isActive)
                .filter(a -> !a.isAdmin())
                .orElse(null);
        if (account == null) {
            audit.record(AuditService.Type.RECOVERY_FAILED, AuditService.Outcome.FAILURE, null, info, null,
                    "method=magic_link invalid, expired or used token");
            throw ApiException.unauthorized("invalid_token", "Invalid or expired recovery link.");
        }
        return resetCertificates(account, key, request.label(), IssuedCertificate.IssuedVia.RECOVERY_MAGIC_LINK, info);
    }

    // ---------------------------------------------------------------- common

    private Dtos.IssuedResponse resetCertificates(Account account, PublicKey key, String label,
                                                  IssuedCertificate.IssuedVia via, RequestInfo info) {
        // The lost certificate may be in an attacker's hands: revoke all of them.
        int revoked = certificates.revokeAllActive(account, IssuedCertificate.Reason.KEY_COMPROMISE,
                "self-service recovery", info);
        tokens.invalidateAll(account);
        CertificateService.IssuedBundle bundle = certificates.issue(account, key, label, via, info);
        audit.record(AuditService.Type.RECOVERY_COMPLETED, AuditService.Outcome.SUCCESS, account.getUsername(), info,
                bundle.record().getSerialHex(), "method=" + via + " revoked=" + revoked);
        notifications.send(account.getEmail(), "Your certificates were reset",
                "A certificate reset was completed for '" + account.getUsername() + "' using " + via
                        + " from IP " + info.ip() + ".\n" + revoked
                        + " previous certificate(s) were revoked and all sessions were closed.");
        return new Dtos.IssuedResponse(bundle.record().getSerialHex(), bundle.record().getNotAfter(),
                bundle.record().getSubjectDn(), bundle.certificatePem(), bundle.chainPem(), null,
                "Certificate issued. " + revoked + " previous certificate(s) revoked, all sessions closed.");
    }
}
