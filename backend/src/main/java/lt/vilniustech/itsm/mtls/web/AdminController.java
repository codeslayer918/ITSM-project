package lt.vilniustech.itsm.mtls.web;

import java.util.List;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import lt.vilniustech.itsm.mtls.auth.AuthContext;
import lt.vilniustech.itsm.mtls.domain.AuditEvent;
import lt.vilniustech.itsm.mtls.pki.CrlPublisher;
import lt.vilniustech.itsm.mtls.service.AdminService;
import lt.vilniustech.itsm.mtls.service.AuditService;
import lt.vilniustech.itsm.mtls.web.dto.Dtos;

/**
 * Administration. SessionAuthFilter requires role ADMIN and a certificate with OU=admins; every
 * handler also checks it again with AuthContext.requireAdmin (defence in depth).
 */
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private static final Dtos.RevokeRequest NO_OPTIONS = new Dtos.RevokeRequest(null, false);

    private final AdminService admin;
    private final AuditService audit;
    private final CrlPublisher crlPublisher;

    public AdminController(AdminService admin, AuditService audit, CrlPublisher crlPublisher) {
        this.admin = admin;
        this.audit = audit;
        this.crlPublisher = crlPublisher;
    }

    @GetMapping("/users")
    public List<Dtos.AccountView> users(HttpServletRequest request) {
        AuthContext.requireAdmin(request);
        return admin.listAccounts();
    }

    @PostMapping("/users")
    @ResponseStatus(HttpStatus.CREATED)
    public Dtos.EnrollmentTokenResponse createUser(HttpServletRequest request,
                                                   @Valid @RequestBody Dtos.CreateUserRequest body) {
        return admin.createUser(body, AuthContext.requireAdmin(request));
    }

    @PostMapping("/users/{username}/enrollment-token")
    public Dtos.EnrollmentTokenResponse enrollmentToken(HttpServletRequest request, @PathVariable String username) {
        return admin.reissueEnrollmentToken(username, AuthContext.requireAdmin(request));
    }

    @PostMapping("/users/{username}/revoke")
    public Dtos.RevocationResult revokeUser(HttpServletRequest request, @PathVariable String username,
                                            @RequestBody(required = false) Dtos.RevokeRequest body) {
        return admin.revokeUser(username, body == null ? NO_OPTIONS : body, AuthContext.requireAdmin(request));
    }

    @PostMapping("/users/{username}/enable")
    public Dtos.EnrollmentTokenResponse enableUser(HttpServletRequest request, @PathVariable String username) {
        return admin.enableUser(username, AuthContext.requireAdmin(request));
    }

    @GetMapping("/certificates")
    public List<Dtos.CertificateView> certificates(HttpServletRequest request) {
        AuthContext.requireAdmin(request);
        return admin.listCertificates();
    }

    @PostMapping("/certificates/{serial}/revoke")
    public Map<String, String> revokeCertificate(HttpServletRequest request, @PathVariable String serial,
                                                 @RequestBody(required = false) Dtos.RevokeRequest body) {
        admin.revokeCertificate(serial, body == null ? NO_OPTIONS : body, AuthContext.requireAdmin(request));
        return Map.of("message", "Certificate revoked.");
    }

    @GetMapping("/groups")
    public Map<String, Long> groups(HttpServletRequest request) {
        AuthContext.requireAdmin(request);
        return admin.listGroups();
    }

    @PostMapping("/groups/{group}/revoke")
    public Dtos.RevocationResult revokeGroup(HttpServletRequest request, @PathVariable String group,
                                             @RequestBody(required = false) Dtos.RevokeRequest body) {
        return admin.revokeGroup(group, body == null ? NO_OPTIONS : body, AuthContext.requireAdmin(request));
    }

    @GetMapping("/audit")
    public List<AuditEvent> auditLog(HttpServletRequest request) {
        AuthContext.requireAdmin(request);
        return audit.latest();
    }

    @PostMapping("/crl/publish")
    public Map<String, Object> publishCrl(HttpServletRequest request) {
        AuthContext auth = AuthContext.requireAdmin(request);
        long number = crlPublisher.publish("manual, by " + auth.username());
        audit.record(AuditService.Type.CRL_PUBLISHED, AuditService.Outcome.SUCCESS, auth.username(),
                auth.requestInfo(), null, "crlNumber=" + number);
        return Map.of("crlNumber", number, "message", "CRL regenerated; nginx reloads it within a few seconds.");
    }
}
