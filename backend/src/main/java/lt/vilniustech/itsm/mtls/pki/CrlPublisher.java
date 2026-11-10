package lt.vilniustech.itsm.mtls.pki;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

import lt.vilniustech.itsm.mtls.config.AppProperties;
import lt.vilniustech.itsm.mtls.domain.IssuedCertificate;
import lt.vilniustech.itsm.mtls.repo.IssuedCertificateRepository;

/**
 * Infrastructure-level revocation: regenerates the Users CA CRL and writes the bundle
 * (root CRL + Users CA CRL) that nginx loads with ssl_crl. The nginx container watches
 * this file and reloads itself when it changes.
 *
 * The CRL is regenerated after every revocation, at startup and periodically, so that it
 * never reaches its nextUpdate date (an expired CRL makes nginx reject everybody).
 */
@Service
public class CrlPublisher implements SmartInitializingSingleton {

    /** Published after a transaction that revoked at least one certificate. */
    public record CertificatesRevokedEvent(int count) {
    }

    private static final Logger log = LoggerFactory.getLogger(CrlPublisher.class);

    private final CertificateAuthority ca;
    private final IssuedCertificateRepository certificates;
    private final JdbcTemplate jdbc;
    private final AppProperties.Pki pki;
    private volatile byte[] currentCrlDer = new byte[0];

    public CrlPublisher(CertificateAuthority ca, IssuedCertificateRepository certificates, JdbcTemplate jdbc,
                        AppProperties props) {
        this.ca = ca;
        this.certificates = certificates;
        this.jdbc = jdbc;
        this.pki = props.pki();
    }

    /** Runs before the web server starts, so the CRL exists before nginx needs it. */
    @Override
    public void afterSingletonsInstantiated() {
        publish("startup");
    }

    @Scheduled(initialDelayString = "PT10M", fixedDelayString = "PT10M")
    public void scheduledRefresh() {
        publish("scheduled refresh");
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT, fallbackExecution = true)
    public void onRevocation(CertificatesRevokedEvent event) {
        publish(event.count() + " certificate(s) revoked");
    }

    public synchronized long publish(String trigger) {
        Long crlNumber = jdbc.queryForObject(
                "update crl_state set crl_number = crl_number + 1 where id = 1 returning crl_number", Long.class);
        List<CertificateAuthority.RevokedEntry> entries = certificates.findByStatus(IssuedCertificate.Status.REVOKED)
                .stream()
                .map(c -> new CertificateAuthority.RevokedEntry(new BigInteger(c.getSerialHex(), 16), c.getRevokedAt(),
                        c.getRevocationReason() == null ? 0 : c.getRevocationReason().code))
                .toList();
        X509CRL crl = ca.generateCrl(entries, crlNumber, pki.crlValidity());
        try {
            String rootCrl = Files.readString(pki.rootCaCrl(), StandardCharsets.US_ASCII);
            String bundle = rootCrl.strip() + "\n" + PemUtils.toPem(crl);
            Path target = pki.crlBundleOutput();
            Files.createDirectories(target.getParent());
            Path tmp = target.resolveSibling(target.getFileName() + ".tmp");
            Files.writeString(tmp, bundle, StandardCharsets.US_ASCII);
            // Atomic replace: nginx never reads a half-written file.
            Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            currentCrlDer = crl.getEncoded();
        } catch (IOException | CRLException e) {
            throw new IllegalStateException("Cannot publish the CRL", e);
        }
        log.info("CRL #{} published ({} revoked serials, trigger: {})", crlNumber, entries.size(), trigger);
        return crlNumber;
    }

    public byte[] currentCrlDer() {
        return currentCrlDer.clone();
    }
}
