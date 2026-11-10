package lt.vilniustech.itsm.mtls.web;

import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import lt.vilniustech.itsm.mtls.auth.RequestInfo;
import lt.vilniustech.itsm.mtls.pki.CrlPublisher;
import lt.vilniustech.itsm.mtls.service.CertificateService;
import lt.vilniustech.itsm.mtls.service.EnrollmentService;
import lt.vilniustech.itsm.mtls.service.RecoveryService;
import lt.vilniustech.itsm.mtls.web.dto.Dtos;

/**
 * Endpoints of the public listener (no client certificate): enrolment, recovery and the
 * CRL distribution point. They are rate limited (nginx + application).
 */
@RestController
public class PublicController {

    private final EnrollmentService enrollment;
    private final RecoveryService recovery;
    private final CrlPublisher crlPublisher;
    private final CertificateService certificates;

    public PublicController(EnrollmentService enrollment, RecoveryService recovery, CrlPublisher crlPublisher,
                            CertificateService certificates) {
        this.enrollment = enrollment;
        this.recovery = recovery;
        this.crlPublisher = crlPublisher;
        this.certificates = certificates;
    }

    @PostMapping("/api/enroll")
    public Dtos.IssuedResponse enroll(HttpServletRequest request, @Valid @RequestBody Dtos.EnrollRequest body) {
        return enrollment.enroll(body, RequestInfo.of(request));
    }

    @PostMapping("/api/recovery/backup-code")
    public Dtos.IssuedResponse recoverWithBackupCode(HttpServletRequest request,
                                                     @Valid @RequestBody Dtos.BackupCodeRecoveryRequest body) {
        return recovery.recoverWithBackupCode(body, RequestInfo.of(request));
    }

    @PostMapping("/api/recovery/magic-link")
    public ResponseEntity<Map<String, String>> requestMagicLink(HttpServletRequest request,
                                                                @Valid @RequestBody Dtos.MagicLinkRequest body) {
        String message = recovery.requestMagicLink(body, RequestInfo.of(request));
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(Map.of("message", message));
    }

    @PostMapping("/api/recovery/magic-link/complete")
    public Dtos.IssuedResponse completeMagicLink(HttpServletRequest request,
                                                 @Valid @RequestBody Dtos.MagicLinkCompleteRequest body) {
        return recovery.completeMagicLink(body, RequestInfo.of(request));
    }

    /** CRL distribution point (the URL written in every client certificate). */
    @GetMapping("/crl/users-ca.crl")
    public ResponseEntity<byte[]> crl() {
        return ResponseEntity.ok().contentType(MediaType.parseMediaType("application/pkix-crl"))
                .body(crlPublisher.currentCrlDer());
    }

    @GetMapping("/ca/chain.pem")
    public ResponseEntity<String> chain() {
        return ResponseEntity.ok().contentType(MediaType.parseMediaType("application/x-pem-file"))
                .body(certificates.chainPem());
    }
}
