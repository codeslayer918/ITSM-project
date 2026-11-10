package lt.vilniustech.itsm.mtls.service;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.regex.Pattern;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import lt.vilniustech.itsm.mtls.auth.RequestInfo;
import lt.vilniustech.itsm.mtls.config.AppProperties;
import lt.vilniustech.itsm.mtls.domain.Account;
import lt.vilniustech.itsm.mtls.domain.IssuedCertificate;
import lt.vilniustech.itsm.mtls.pki.CertificateAuthority;
import lt.vilniustech.itsm.mtls.pki.CrlPublisher;
import lt.vilniustech.itsm.mtls.pki.PemUtils;
import lt.vilniustech.itsm.mtls.repo.IssuedCertificateRepository;
import lt.vilniustech.itsm.mtls.web.ApiException;

/** Issues and revokes client certificates. Every revocation triggers a new CRL after commit. */
@Service
public class CertificateService {

    /** What the user receives: the certificate and the chain to build the PKCS#12 locally. */
    public record IssuedBundle(IssuedCertificate record, String certificatePem, String chainPem) {
    }

    private static final Pattern LABEL = Pattern.compile("^[A-Za-z0-9 ._-]{1,64}$");

    private final CertificateAuthority ca;
    private final IssuedCertificateRepository certificates;
    private final AuditService audit;
    private final NotificationService notifications;
    private final ApplicationEventPublisher events;
    private final AppProperties.Pki pki;
    private final String chainPem;

    public CertificateService(CertificateAuthority ca, IssuedCertificateRepository certificates, AuditService audit,
                              NotificationService notifications, ApplicationEventPublisher events,
                              AppProperties props) {
        this.ca = ca;
        this.certificates = certificates;
        this.audit = audit;
        this.notifications = notifications;
        this.events = events;
        this.pki = props.pki();
        try {
            this.chainPem = Files.readString(pki.usersCaChain(), StandardCharsets.US_ASCII);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Transactional
    public IssuedBundle issue(Account account, PublicKey key, String label, IssuedCertificate.IssuedVia via,
                              RequestInfo info) {
        if (!account.isActive()) {
            throw ApiException.forbidden("account_disabled", "This account is disabled.");
        }
        String deviceLabel = label == null || label.isBlank() ? "device" : label.strip();
        if (!LABEL.matcher(deviceLabel).matches()) {
            throw ApiException.badRequest("invalid_label", "The device label may contain letters, digits, space, '.', '_' and '-' (max 64).");
        }
        // A key pair is used for one certificate only: a key that was ever certified
        // (and maybe revoked as compromised) cannot come back with a new certificate.
        String spki = PemUtils.spkiFingerprint(key);
        if (certificates.existsBySpkiSha256(spki)) {
            throw ApiException.conflict("key_reuse", "This key pair was already certified. Generate a new key.");
        }
        long active = certificates.countByAccountAndStatus(account, IssuedCertificate.Status.ACTIVE);
        if (active >= pki.maxActiveCertificates()) {
            throw ApiException.conflict("too_many_certificates",
                    "Maximum of " + pki.maxActiveCertificates() + " active certificates reached. Revoke one first.");
        }

        X509Certificate cert = ca.issueClientCertificate(key, account.getUsername(), account.getGroup(),
                account.getEmail(), pki.clientCertValidity());
        IssuedCertificate record = certificates.save(new IssuedCertificate(account, PemUtils.serialHex(cert),
                PemUtils.fingerprint(cert), spki, cert.getSubjectX500Principal().getName(), account.getGroup(),
                deviceLabel, via, cert.getNotBefore().toInstant(), cert.getNotAfter().toInstant()));

        audit.record(AuditService.Type.CERTIFICATE_ISSUED, AuditService.Outcome.SUCCESS, account.getUsername(), info,
                record.getSerialHex(), "via=" + via + " label=" + deviceLabel);
        notifications.send(account.getEmail(), "New certificate issued",
                "A new client certificate was issued for your account '" + account.getUsername() + "'.\n"
                        + "Device: " + deviceLabel + "\nMethod: " + via + "\nSerial: " + record.getSerialHex()
                        + "\nFrom IP: " + (info == null ? "-" : info.ip()));
        return new IssuedBundle(record, PemUtils.toPem(cert), chainPem);
    }

    @Transactional
    public void revoke(IssuedCertificate cert, IssuedCertificate.Reason reason, String actor, RequestInfo info) {
        if (!cert.isActive()) {
            return;
        }
        cert.revoke(reason);
        Account account = cert.getAccount();
        // Sessions opened with this certificate are rejected by SessionAuthFilter on their
        // next request (status check); bump the epoch too so that no stale state survives.
        account.invalidateAllSessions();
        audit.record(AuditService.Type.CERTIFICATE_REVOKED, AuditService.Outcome.SUCCESS, account.getUsername(), info,
                cert.getSerialHex(), "reason=" + reason + " by=" + actor);
        notifications.send(account.getEmail(), "Certificate revoked",
                "The certificate '" + cert.getDeviceLabel() + "' (serial " + cert.getSerialHex()
                        + ") of your account was revoked by " + actor + ". Reason: " + reason + ".");
        events.publishEvent(new CrlPublisher.CertificatesRevokedEvent(1));
    }

    /** Revokes every active certificate of the account and invalidates its sessions. */
    @Transactional
    public int revokeAllActive(Account account, IssuedCertificate.Reason reason, String actor, RequestInfo info) {
        List<IssuedCertificate> active = certificates.findByAccountAndStatus(account, IssuedCertificate.Status.ACTIVE);
        active.forEach(c -> {
            c.revoke(reason);
            audit.record(AuditService.Type.CERTIFICATE_REVOKED, AuditService.Outcome.SUCCESS, account.getUsername(),
                    info, c.getSerialHex(), "reason=" + reason + " by=" + actor);
        });
        account.invalidateAllSessions();
        if (!active.isEmpty()) {
            events.publishEvent(new CrlPublisher.CertificatesRevokedEvent(active.size()));
        }
        return active.size();
    }

    /** Group revocation: every active certificate whose OU is the group. */
    @Transactional
    public int revokeGroup(String group, IssuedCertificate.Reason reason, String actor, RequestInfo info) {
        List<IssuedCertificate> active = certificates.findByGroupAndStatus(group, IssuedCertificate.Status.ACTIVE);
        active.forEach(c -> {
            c.revoke(reason);
            c.getAccount().invalidateAllSessions();
            audit.record(AuditService.Type.CERTIFICATE_REVOKED, AuditService.Outcome.SUCCESS,
                    c.getAccount().getUsername(), info, c.getSerialHex(),
                    "reason=" + reason + " by=" + actor + " (group " + group + ")");
        });
        if (!active.isEmpty()) {
            events.publishEvent(new CrlPublisher.CertificatesRevokedEvent(active.size()));
        }
        return active.size();
    }

    public String chainPem() {
        return chainPem;
    }
}
