package lt.vilniustech.itsm.mtls.pki;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * The "Users" intermediate CA. It signs client certificates from CSRs (the private key
 * of the user never leaves the user's machine) and signs the CRL.
 * The Root CA key is never loaded here: it stays offline.
 */
public class CertificateAuthority {

    public static final String CLIENT_AUTH_OID = KeyPurposeId.id_kp_clientAuth.getId();

    /** One entry of the CRL. */
    public record RevokedEntry(BigInteger serial, Instant revokedAt, int reasonCode) {
    }

    private final X509Certificate caCert;
    private final PrivateKey caKey;
    private final String organization;
    private final String crlDistributionUrl;
    private final String signatureAlgorithm;
    private final SecureRandom random = new SecureRandom();

    public CertificateAuthority(X509Certificate caCert, PrivateKey caKey, String organization,
                                String crlDistributionUrl) {
        this.caCert = caCert;
        this.caKey = caKey;
        this.organization = organization;
        this.crlDistributionUrl = crlDistributionUrl;
        this.signatureAlgorithm = switch (caKey.getAlgorithm()) {
            case "EC", "ECDSA" -> "SHA384withECDSA";
            case "RSA" -> "SHA256withRSA";
            default -> throw new IllegalArgumentException("Unsupported CA key algorithm " + caKey.getAlgorithm());
        };
    }

    public X509Certificate getCaCertificate() {
        return caCert;
    }

    /**
     * Issues a client certificate. The subject is built by the CA from the account
     * (CN=username, OU=group). The subject and extensions requested in the CSR are ignored,
     * so a user cannot ask for another identity, another group or the CA flag.
     */
    public X509Certificate issueClientCertificate(PublicKey subjectKey, String username, String group,
                                                  String email, Duration validity) {
        try {
            Instant now = Instant.now();
            X500Name subject = new X500NameBuilder(BCStyle.INSTANCE)
                    .addRDN(BCStyle.O, organization)
                    .addRDN(BCStyle.OU, group)
                    .addRDN(BCStyle.CN, username)
                    .build();
            // 127 random bits: unpredictable, positive, fits in 20 octets (RFC 5280 4.1.2.2).
            BigInteger serial = new BigInteger(127, random).setBit(120);

            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    caCert, serial,
                    Date.from(now.minus(Duration.ofMinutes(5))),   // small clock-skew allowance
                    Date.from(now.plus(validity)),
                    subject, subjectKey);

            JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
            builder.addExtension(Extension.extendedKeyUsage, false,
                    new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth));
            builder.addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(subjectKey));
            builder.addExtension(Extension.authorityKeyIdentifier, false, ext.createAuthorityKeyIdentifier(caCert));
            builder.addExtension(Extension.subjectAlternativeName, false,
                    new GeneralNames(new GeneralName(GeneralName.rfc822Name, email)));
            builder.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(new DistributionPoint[]{
                    new DistributionPoint(new DistributionPointName(new GeneralNames(
                            new GeneralName(GeneralName.uniformResourceIdentifier, crlDistributionUrl))),
                            null, null)}));

            X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC")
                    .getCertificate(builder.build(signer()));
            cert.verify(caCert.getPublicKey());
            return cert;
        } catch (Exception e) {
            throw new IllegalStateException("Certificate issuance failed", e);
        }
    }

    /** Builds and signs a CRL listing every revoked serial. */
    public X509CRL generateCrl(List<RevokedEntry> entries, long crlNumber, Duration validity) {
        try {
            Instant now = Instant.now();
            X509v2CRLBuilder builder = new JcaX509v2CRLBuilder(caCert.getSubjectX500Principal(), Date.from(now));
            builder.setNextUpdate(Date.from(now.plus(validity)));
            for (RevokedEntry entry : entries) {
                builder.addCRLEntry(entry.serial(), Date.from(entry.revokedAt()), entry.reasonCode());
            }
            builder.addExtension(Extension.authorityKeyIdentifier, false,
                    new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(caCert));
            builder.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf(crlNumber)));
            X509CRLHolder holder = builder.build(signer());
            X509CRL crl = new JcaX509CRLConverter().setProvider("BC").getCRL(holder);
            crl.verify(caCert.getPublicKey());
            return crl;
        } catch (Exception e) {
            throw new IllegalStateException("CRL generation failed", e);
        }
    }

    /** True if the certificate was signed by this CA (checked again by the backend, after nginx). */
    public boolean isIssuedByThisCa(X509Certificate cert) {
        if (!cert.getIssuerX500Principal().equals(caCert.getSubjectX500Principal())) {
            return false;
        }
        try {
            cert.verify(caCert.getPublicKey());
            return true;
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    private ContentSigner signer() throws Exception {
        return new JcaContentSignerBuilder(signatureAlgorithm).setProvider("BC").build(caKey);
    }
}
