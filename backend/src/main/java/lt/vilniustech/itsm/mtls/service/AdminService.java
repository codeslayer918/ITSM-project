package lt.vilniustech.itsm.mtls.service;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import lt.vilniustech.itsm.mtls.auth.AuthContext;
import lt.vilniustech.itsm.mtls.config.AppProperties;
import lt.vilniustech.itsm.mtls.domain.Account;
import lt.vilniustech.itsm.mtls.domain.IssuedCertificate;
import lt.vilniustech.itsm.mtls.domain.OneTimeToken;
import lt.vilniustech.itsm.mtls.repo.AccountRepository;
import lt.vilniustech.itsm.mtls.repo.IssuedCertificateRepository;
import lt.vilniustech.itsm.mtls.web.ApiException;
import lt.vilniustech.itsm.mtls.web.dto.Dtos;

/** Centralised administration: accounts, enrolment invitations and revocation (user / group / certificate). */
@Service
public class AdminService {

    private final AccountRepository accounts;
    private final IssuedCertificateRepository certificates;
    private final CertificateService certificateService;
    private final BackupCodeService backupCodes;
    private final TokenService tokens;
    private final NotificationService notifications;
    private final AuditService audit;
    private final AppProperties props;

    public AdminService(AccountRepository accounts, IssuedCertificateRepository certificates,
                        CertificateService certificateService, BackupCodeService backupCodes, TokenService tokens,
                        NotificationService notifications, AuditService audit, AppProperties props) {
        this.accounts = accounts;
        this.certificates = certificates;
        this.certificateService = certificateService;
        this.backupCodes = backupCodes;
        this.tokens = tokens;
        this.notifications = notifications;
        this.audit = audit;
        this.props = props;
    }

    @Transactional(readOnly = true)
    public List<Dtos.AccountView> listAccounts() {
        return accounts.findAllByOrderByUsernameAsc().stream()
                .map(a -> Dtos.AccountView.of(a,
                        certificates.countByAccountAndStatus(a, IssuedCertificate.Status.ACTIVE),
                        backupCodes.remaining(a)))
                .toList();
    }

    @Transactional(readOnly = true)
    public List<Dtos.CertificateView> listCertificates() {
        return certificates.findAllWithAccount().stream()
                .map(c -> Dtos.CertificateView.of(c, true, null))
                .toList();
    }

    /** Group name -> number of active certificates. */
    @Transactional(readOnly = true)
    public Map<String, Long> listGroups() {
        Map<String, Long> groups = new TreeMap<>();
        accounts.findAll().forEach(a -> groups.putIfAbsent(a.getGroup(), 0L));
        certificates.findByStatus(IssuedCertificate.Status.ACTIVE)
                .forEach(c -> groups.merge(c.getGroup(), 1L, Long::sum));
        return groups;
    }

    @Transactional
    public Dtos.EnrollmentTokenResponse createUser(Dtos.CreateUserRequest request, AuthContext admin) {
        if (accounts.existsByUsername(request.username()) || accounts.existsByEmailIgnoreCase(request.email())) {
            throw ApiException.conflict("account_exists", "An account with this username or e-mail already exists.");
        }
        Account account = accounts.save(new Account(request.username(), request.email().toLowerCase(), request.group()));
        return newEnrollmentToken(account, admin);
    }

    /** New invitation (e.g. the user never enrolled, or after re-enabling the account). */
    @Transactional
    public Dtos.EnrollmentTokenResponse reissueEnrollmentToken(String username, AuthContext admin) {
        Account account = findAccount(username);
        if (!account.isActive()) {
            throw ApiException.conflict("account_disabled", "Enable the account first.");
        }
        return newEnrollmentToken(account, admin);
    }

    @Transactional
    public Dtos.RevocationResult revokeUser(String username, Dtos.RevokeRequest request, AuthContext admin) {
        Account account = findAccount(username);
        if (account.getId().equals(admin.accountId()) && request.disable()) {
            throw ApiException.conflict("self_lockout", "You cannot disable your own account.");
        }
        IssuedCertificate.Reason reason = request.parsedReason(IssuedCertificate.Reason.UNSPECIFIED);
        int revoked = certificateService.revokeAllActive(account, reason, "admin " + admin.username(),
                admin.requestInfo());
        if (request.disable()) {
            disable(account);
        }
        audit.record(AuditService.Type.USER_REVOKED, AuditService.Outcome.SUCCESS, account.getUsername(),
                admin.requestInfo(), null, "by=" + admin.username() + " reason=" + reason + " revoked=" + revoked
                        + " disabled=" + request.disable());
        notifications.send(account.getEmail(), "Your certificates were revoked",
                revoked + " certificate(s) of your account were revoked by an administrator."
                        + (request.disable() ? " Your account is disabled." : ""));
        return new Dtos.RevocationResult(revoked, 1, request.disable());
    }

    @Transactional
    public Dtos.RevocationResult revokeGroup(String group, Dtos.RevokeRequest request, AuthContext admin) {
        if (Account.ADMIN_GROUP.equals(group)) {
            throw ApiException.conflict("self_lockout",
                    "Revoking the whole admins group would lock every administrator out. Revoke admins one by one.");
        }
        List<Account> members = accounts.findByGroup(group);
        if (members.isEmpty()) {
            throw ApiException.notFound("Unknown group.");
        }
        IssuedCertificate.Reason reason = request.parsedReason(IssuedCertificate.Reason.AFFILIATION_CHANGED);
        int revoked = certificateService.revokeGroup(group, reason, "admin " + admin.username(), admin.requestInfo());
        members.forEach(a -> {
            a.invalidateAllSessions();
            if (request.disable()) {
                disable(a);
            }
            notifications.send(a.getEmail(), "Group certificates revoked",
                    "All certificates of group '" + group + "' were revoked by an administrator."
                            + (request.disable() ? " Your account is disabled." : ""));
        });
        audit.record(AuditService.Type.GROUP_REVOKED, AuditService.Outcome.SUCCESS, null, admin.requestInfo(), null,
                "group=" + group + " by=" + admin.username() + " reason=" + reason + " revoked=" + revoked
                        + " accounts=" + members.size() + " disabled=" + request.disable());
        return new Dtos.RevocationResult(revoked, members.size(), request.disable());
    }

    @Transactional
    public void revokeCertificate(String serial, Dtos.RevokeRequest request, AuthContext admin) {
        IssuedCertificate cert = java.util.Optional.ofNullable(lt.vilniustech.itsm.mtls.pki.PemUtils.normalizeSerial(serial))
                .flatMap(certificates::findBySerialHex)
                .orElseThrow(() -> ApiException.notFound("Unknown certificate."));
        certificateService.revoke(cert, request.parsedReason(IssuedCertificate.Reason.UNSPECIFIED),
                "admin " + admin.username(), admin.requestInfo());
    }

    /**
     * Re-enables a disabled account. Old backup codes are deleted (they may be known to the
     * attacker that caused the revocation); the user gets a fresh invitation and new codes.
     */
    @Transactional
    public Dtos.EnrollmentTokenResponse enableUser(String username, AuthContext admin) {
        Account account = findAccount(username);
        account.setStatus(Account.Status.ACTIVE);
        backupCodes.deleteAll(account);
        audit.record(AuditService.Type.USER_ENABLED, AuditService.Outcome.SUCCESS, account.getUsername(),
                admin.requestInfo(), null, "by=" + admin.username());
        return newEnrollmentToken(account, admin);
    }

    private void disable(Account account) {
        account.setStatus(Account.Status.DISABLED);
        account.invalidateAllSessions();
        // A disabled account can neither recover nor enrol.
        tokens.invalidateAll(account);
    }

    private Dtos.EnrollmentTokenResponse newEnrollmentToken(Account account, AuthContext admin) {
        String token = tokens.issue(account, OneTimeToken.Purpose.ENROLLMENT, props.tokens().enrollmentValidity());
        Instant expires = Instant.now().plus(props.tokens().enrollmentValidity());
        String url = props.publicBaseUrl() + "/enroll.html#token=" + token;
        notifications.send(account.getEmail(), "Enrol your client certificate",
                "An administrator invited '" + account.getUsername() + "' to enrol a client certificate.\n"
                        + "Enrolment link (single use, valid " + props.tokens().enrollmentValidity().toHours()
                        + " h):\n" + url);
        audit.record(AuditService.Type.ENROLLMENT_TOKEN_CREATED, AuditService.Outcome.SUCCESS, account.getUsername(),
                admin == null ? null : admin.requestInfo(), null, "by=" + (admin == null ? "bootstrap" : admin.username()));
        return new Dtos.EnrollmentTokenResponse(account.getUsername(), token, expires, url);
    }

    private Account findAccount(String username) {
        return accounts.findByUsername(username).orElseThrow(() -> ApiException.notFound("Unknown user."));
    }
}
