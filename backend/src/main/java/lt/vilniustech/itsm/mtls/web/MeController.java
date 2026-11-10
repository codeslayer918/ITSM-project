package lt.vilniustech.itsm.mtls.web;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lt.vilniustech.itsm.mtls.auth.AuthContext;
import lt.vilniustech.itsm.mtls.auth.SessionKeys;
import lt.vilniustech.itsm.mtls.service.SelfService;
import lt.vilniustech.itsm.mtls.web.dto.Dtos;

/** Self-service endpoints (mTLS listener + session, see SessionAuthFilter). */
@RestController
@RequestMapping("/api/me")
public class MeController {

    private final SelfService selfService;

    public MeController(SelfService selfService) {
        this.selfService = selfService;
    }

    @GetMapping
    public Dtos.MeView me(HttpServletRequest request) {
        Instant loginAt = (Instant) request.getSession(false).getAttribute(SessionKeys.LOGIN_AT);
        return selfService.me(AuthContext.require(request), loginAt);
    }

    @GetMapping("/certificates")
    public List<Dtos.CertificateView> certificates(HttpServletRequest request) {
        return selfService.myCertificates(AuthContext.require(request));
    }

    /** Adds a certificate for another device (backup authentication method). */
    @PostMapping("/certificates")
    public Dtos.IssuedResponse addDevice(HttpServletRequest request, @Valid @RequestBody Dtos.CsrRequest body) {
        return selfService.addDevice(AuthContext.require(request), body);
    }

    @PostMapping("/certificates/{serial}/revoke")
    public Map<String, String> revoke(HttpServletRequest request, @PathVariable String serial) {
        selfService.revokeOwn(AuthContext.require(request), serial);
        return Map.of("message", "Certificate revoked.");
    }

    @PostMapping("/backup-codes")
    public Dtos.BackupCodesResponse regenerateBackupCodes(HttpServletRequest request) {
        return selfService.regenerateBackupCodes(AuthContext.require(request));
    }
}
