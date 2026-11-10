package lt.vilniustech.itsm.mtls.web.dto;

import java.time.Instant;
import java.util.List;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import lt.vilniustech.itsm.mtls.domain.Account;
import lt.vilniustech.itsm.mtls.domain.IssuedCertificate;

/** Request and response bodies of the JSON API. */
public final class Dtos {

    private Dtos() {
    }

    // ------------------------------------------------------------------ requests

    public record CsrRequest(@NotBlank @Size(max = 8192) String csr, @Size(max = 64) String label) {
    }

    public record EnrollRequest(@NotBlank @Size(max = 128) String token,
                                @NotBlank @Size(max = 8192) String csr,
                                @Size(max = 64) String label) {
    }

    public record BackupCodeRecoveryRequest(@NotBlank @Size(max = 32) String username,
                                            @NotBlank @Size(max = 64) String backupCode,
                                            @NotBlank @Size(max = 8192) String csr,
                                            @Size(max = 64) String label) {
    }

    public record MagicLinkRequest(@NotBlank @Email @Size(max = 254) String email) {
    }

    public record MagicLinkCompleteRequest(@NotBlank @Size(max = 128) String token,
                                           @NotBlank @Size(max = 8192) String csr,
                                           @Size(max = 64) String label) {
    }

    public record CreateUserRequest(
            @NotBlank @Pattern(regexp = "^[a-z0-9][a-z0-9._-]{2,31}$") String username,
            @NotBlank @Email @Size(max = 254) String email,
            @NotBlank @Pattern(regexp = "^[a-z0-9][a-z0-9-]{1,31}$") String group) {
    }

    public record RevokeRequest(String reason, Boolean disableAccount) {

        public IssuedCertificate.Reason parsedReason(IssuedCertificate.Reason fallback) {
            if (reason == null || reason.isBlank()) {
                return fallback;
            }
            try {
                return IssuedCertificate.Reason.valueOf(reason.trim().toUpperCase().replace('-', '_'));
            } catch (IllegalArgumentException e) {
                return fallback;
            }
        }

        public boolean disable() {
            return Boolean.TRUE.equals(disableAccount);
        }
    }

    // ----------------------------------------------------------------- responses

    public record CertificateView(String serial, String username, String group, String label, String status,
                                  String issuedVia, Instant notBefore, Instant notAfter, Instant revokedAt,
                                  String revocationReason, Boolean current) {

        public static CertificateView of(IssuedCertificate c, boolean includeUser, String currentSerial) {
            return new CertificateView(c.getSerialHex(), includeUser ? c.getAccount().getUsername() : null,
                    c.getGroup(), c.getDeviceLabel(), c.getStatus().name(), c.getIssuedVia().name(),
                    c.getNotBefore(), c.getNotAfter(), c.getRevokedAt(),
                    c.getRevocationReason() == null ? null : c.getRevocationReason().name(),
                    currentSerial == null ? null : c.getSerialHex().equals(currentSerial));
        }
    }

    public record IssuedResponse(String serial, Instant notAfter, String subject, String certificatePem,
                                 String chainPem, List<String> backupCodes, String message) {
    }

    public record AccountView(String username, String email, String group, String role, String status,
                              long activeCertificates, long backupCodesRemaining, Instant createdAt) {

        public static AccountView of(Account a, long activeCertificates, long backupCodesRemaining) {
            return new AccountView(a.getUsername(), a.getEmail(), a.getGroup(), a.getRole().name(),
                    a.getStatus().name(), activeCertificates, backupCodesRemaining, a.getCreatedAt());
        }
    }

    public record MeView(AccountView account, String currentCertificateSerial, String currentCertificateSubject,
                         boolean adminSession, Instant sessionStartedAt) {
    }

    public record EnrollmentTokenResponse(String username, String enrollmentToken, Instant expiresAt,
                                          String enrollmentUrl) {
    }

    public record RevocationResult(int revokedCertificates, int affectedAccounts, boolean accountsDisabled) {
    }

    public record BackupCodesResponse(List<String> backupCodes, String message) {
    }
}
