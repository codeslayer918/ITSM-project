package lt.vilniustech.itsm.mtls.auth;

import java.security.cert.X509Certificate;

/** The client certificate verified by nginx during the TLS handshake, as seen by the backend. */
public record ClientCertificate(
        X509Certificate certificate,
        String fingerprintSha256,
        String serialHex,
        String subjectDn,
        String commonName,
        String organizationalUnit) {
}
