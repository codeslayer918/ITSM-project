package lt.vilniustech.itsm.mtls.auth;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.stereotype.Component;

import lt.vilniustech.itsm.mtls.pki.CertificateAuthority;
import lt.vilniustech.itsm.mtls.pki.PemUtils;
import lt.vilniustech.itsm.mtls.web.ApiException;

/**
 * Reads the client certificate forwarded by nginx and re-checks it (defence in depth):
 * nginx already verified the chain, the validity period and the CRL during the handshake;
 * the backend verifies again that the certificate comes from the Users CA, is within its
 * validity period and carries the clientAuth EKU (OpenSSL accepts a certificate without
 * any EKU, the backend does not).
 */
@Component
public class ClientCertificateExtractor {

    public static final String HEADER_LISTENER = "X-Auth-Listener";
    public static final String HEADER_VERIFY = "X-SSL-Client-Verify";
    public static final String HEADER_CERT = "X-SSL-Client-Cert";
    public static final String LISTENER_MTLS = "mtls";

    private final CertificateAuthority ca;

    public ClientCertificateExtractor(CertificateAuthority ca) {
        this.ca = ca;
    }

    public ClientCertificate extract(HttpServletRequest request) {
        if (!LISTENER_MTLS.equals(request.getHeader(HEADER_LISTENER))) {
            throw ApiException.unauthorized("client_certificate_required", "Use the mutual TLS endpoint.");
        }
        if (!"SUCCESS".equals(request.getHeader(HEADER_VERIFY))) {
            throw ApiException.unauthorized("client_certificate_required", "A valid client certificate is required.");
        }
        String escaped = request.getHeader(HEADER_CERT);
        if (escaped == null || escaped.isBlank()) {
            throw ApiException.unauthorized("client_certificate_required", "A valid client certificate is required.");
        }

        X509Certificate cert;
        try {
            cert = PemUtils.parseCertificate(percentDecode(escaped));
        } catch (IllegalArgumentException e) {
            throw ApiException.unauthorized("client_certificate_invalid", "The client certificate could not be parsed.");
        }
        if (!ca.isIssuedByThisCa(cert)) {
            throw ApiException.forbidden("client_certificate_invalid", "The client certificate was not issued by the Users CA.");
        }
        try {
            cert.checkValidity();
        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            throw ApiException.forbidden("client_certificate_expired", "The client certificate is not valid at this time.");
        }
        if (!hasClientAuthEku(cert)) {
            throw ApiException.forbidden("client_certificate_wrong_eku",
                    "The client certificate is not allowed for TLS client authentication (EKU clientAuth missing).");
        }

        String dn = cert.getSubjectX500Principal().getName();
        return new ClientCertificate(cert, PemUtils.fingerprint(cert), PemUtils.serialHex(cert), dn,
                rdnValue(dn, "CN"), rdnValue(dn, "OU"));
    }

    static boolean hasClientAuthEku(X509Certificate cert) {
        try {
            List<String> eku = cert.getExtendedKeyUsage();
            return eku != null && eku.contains(CertificateAuthority.CLIENT_AUTH_OID);
        } catch (CertificateParsingException e) {
            return false;
        }
    }

    private static String rdnValue(String dn, String type) {
        try {
            for (Rdn rdn : new LdapName(dn).getRdns()) {
                if (rdn.getType().equalsIgnoreCase(type)) {
                    return rdn.getValue().toString();
                }
            }
        } catch (InvalidNameException ignored) {
            // fall through
        }
        return null;
    }

    /**
     * Decodes the URL-encoded PEM of $ssl_client_escaped_cert. A dedicated decoder is used
     * because URLDecoder would turn a literal '+' of the Base64 alphabet into a space.
     */
    static String percentDecode(String value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '%' && i + 2 < value.length()) {
                out.write(Integer.parseInt(value.substring(i + 1, i + 3), 16));
                i += 2;
            } else {
                out.write(c);
            }
        }
        return out.toString(StandardCharsets.US_ASCII);
    }
}
