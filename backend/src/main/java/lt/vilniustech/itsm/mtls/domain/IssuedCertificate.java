package lt.vilniustech.itsm.mtls.domain;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

@Entity
@Table(name = "issued_certificate")
public class IssuedCertificate {

    public enum Status { ACTIVE, REVOKED }

    /** How the certificate was obtained (useful for the audit and the threat model). */
    public enum IssuedVia { ENROLLMENT, ADDITIONAL_DEVICE, RECOVERY_BACKUP_CODE, RECOVERY_MAGIC_LINK }

    /** Subset of the RFC 5280 CRLReason codes used by the application. */
    public enum Reason {
        UNSPECIFIED(0), KEY_COMPROMISE(1), AFFILIATION_CHANGED(3), SUPERSEDED(4), CESSATION_OF_OPERATION(5);

        public final int code;

        Reason(int code) {
            this.code = code;
        }
    }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "account_id")
    private Account account;

    @Column(name = "serial_hex", nullable = false, unique = true)
    private String serialHex;

    @Column(name = "fingerprint_sha256", nullable = false, unique = true)
    private String fingerprintSha256;

    @Column(name = "spki_sha256", nullable = false)
    private String spkiSha256;

    @Column(name = "subject_dn", nullable = false)
    private String subjectDn;

    @Column(name = "group_name", nullable = false)
    private String group;

    @Column(name = "device_label", nullable = false)
    private String deviceLabel;

    @Enumerated(EnumType.STRING)
    @Column(name = "issued_via", nullable = false)
    private IssuedVia issuedVia;

    @Column(name = "not_before", nullable = false)
    private Instant notBefore;

    @Column(name = "not_after", nullable = false)
    private Instant notAfter;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Status status;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Enumerated(EnumType.STRING)
    @Column(name = "revocation_reason")
    private Reason revocationReason;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    protected IssuedCertificate() {
    }

    public IssuedCertificate(Account account, String serialHex, String fingerprintSha256, String spkiSha256,
                             String subjectDn, String group, String deviceLabel, IssuedVia issuedVia,
                             Instant notBefore, Instant notAfter) {
        this.account = account;
        this.serialHex = serialHex;
        this.fingerprintSha256 = fingerprintSha256;
        this.spkiSha256 = spkiSha256;
        this.subjectDn = subjectDn;
        this.group = group;
        this.deviceLabel = deviceLabel;
        this.issuedVia = issuedVia;
        this.notBefore = notBefore;
        this.notAfter = notAfter;
        this.status = Status.ACTIVE;
        this.createdAt = Instant.now();
    }

    public void revoke(Reason reason) {
        if (status == Status.REVOKED) {
            return;
        }
        status = Status.REVOKED;
        revokedAt = Instant.now();
        revocationReason = reason;
    }

    public boolean isActive() {
        return status == Status.ACTIVE;
    }

    public Long getId() { return id; }
    public Account getAccount() { return account; }
    public String getSerialHex() { return serialHex; }
    public String getFingerprintSha256() { return fingerprintSha256; }
    public String getSpkiSha256() { return spkiSha256; }
    public String getSubjectDn() { return subjectDn; }
    public String getGroup() { return group; }
    public String getDeviceLabel() { return deviceLabel; }
    public IssuedVia getIssuedVia() { return issuedVia; }
    public Instant getNotBefore() { return notBefore; }
    public Instant getNotAfter() { return notAfter; }
    public Status getStatus() { return status; }
    public Instant getRevokedAt() { return revokedAt; }
    public Reason getRevocationReason() { return revocationReason; }
    public Instant getCreatedAt() { return createdAt; }
}
