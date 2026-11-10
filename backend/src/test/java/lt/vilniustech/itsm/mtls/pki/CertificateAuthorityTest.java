package lt.vilniustech.itsm.mtls.pki;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import lt.vilniustech.itsm.mtls.web.ApiException;

class CertificateAuthorityTest {

    private static CertificateAuthority ca;
    private static X509Certificate caCert;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyPair caKeys = ecKeyPair("secp384r1");
        X500Name name = new X500Name("O=Test,OU=Users,CN=Test Users CA");
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(name, BigInteger.ONE,
                new Date(), Date.from(Instant.now().plus(Duration.ofDays(30))), name, caKeys.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        caCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(
                builder.build(new JcaContentSignerBuilder("SHA384withECDSA").setProvider("BC").build(caKeys.getPrivate())));
        ca = new CertificateAuthority(caCert, caKeys.getPrivate(), "Test", "https://localhost/crl");
    }

    @Test
    void issuesClientCertificateWithServerChosenSubjectAndClientAuthEku() throws Exception {
        // The CSR asks for another identity and group: it must be ignored.
        String csrPem = csrPem(ecKeyPair("secp256r1"), "CN=root,OU=admins");
        var key = new CsrValidator().validateAndExtractKey(csrPem);

        X509Certificate cert = ca.issueClientCertificate(key, "alice", "staff", "alice@example.test", Duration.ofDays(90));

        assertThat(cert.getSubjectX500Principal().getName()).isEqualTo("CN=alice,OU=staff,O=Test");
        assertThat(cert.getExtendedKeyUsage()).containsExactly(CertificateAuthority.CLIENT_AUTH_OID);
        assertThat(cert.getBasicConstraints()).isEqualTo(-1);           // not a CA
        assertThat(cert.getKeyUsage()[0]).isTrue();                     // digitalSignature
        assertThat(cert.getSerialNumber().bitLength()).isGreaterThan(120);
        assertThat(ca.isIssuedByThisCa(cert)).isTrue();
    }

    @Test
    void rejectsCertificateFromAnotherCa() throws Exception {
        KeyPair other = ecKeyPair("secp256r1");
        X500Name name = new X500Name("O=Test,OU=Users,CN=Test Users CA"); // same name, other key
        X509Certificate forged = new JcaX509CertificateConverter().setProvider("BC").getCertificate(
                new JcaX509v3CertificateBuilder(name, BigInteger.TEN, new Date(),
                        Date.from(Instant.now().plus(Duration.ofDays(1))), new X500Name("CN=alice"), other.getPublic())
                        .build(new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(other.getPrivate())));
        assertThat(ca.isIssuedByThisCa(forged)).isFalse();
    }

    @Test
    void crlContainsRevokedSerials() throws Exception {
        BigInteger serial = new BigInteger("1234567890ABCDEF", 16);
        X509CRL crl = ca.generateCrl(List.of(new CertificateAuthority.RevokedEntry(serial, Instant.now(), 1)),
                42, Duration.ofHours(24));
        crl.verify(caCert.getPublicKey());
        assertThat(crl.getRevokedCertificate(serial)).isNotNull();
        assertThat(crl.getNextUpdate()).isAfter(new Date());
    }

    @Test
    void csrWithBadSignatureOrWeakKeyIsRejected() throws Exception {
        CsrValidator validator = new CsrValidator();
        KeyPair keys = ecKeyPair("secp256r1");
        byte[] der = new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=x"), keys.getPublic())
                .build(new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(keys.getPrivate()))
                .getEncoded();
        der[der.length - 1] ^= 0x01; // corrupt the last byte of the signature
        String tampered = "-----BEGIN CERTIFICATE REQUEST-----\n"
                + java.util.Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der)
                + "\n-----END CERTIFICATE REQUEST-----\n";
        assertThatThrownBy(() -> validator.validateAndExtractKey(tampered))
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("proof of possession");
        assertThatThrownBy(() -> validator.validateAndExtractKey("not a csr")).isInstanceOf(ApiException.class);

        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(1024);
        assertThatThrownBy(() -> validator.validateAndExtractKey(csrPem(rsa.generateKeyPair(), "CN=x", "SHA256withRSA")))
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("2048");
    }

    static KeyPair ecKeyPair(String curve) throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec(curve));
        return gen.generateKeyPair();
    }

    static String csrPem(KeyPair keys, String subject) throws Exception {
        return csrPem(keys, subject, "SHA256withECDSA");
    }

    static String csrPem(KeyPair keys, String subject, String alg) throws Exception {
        var csr = new JcaPKCS10CertificationRequestBuilder(new X500Name(subject), keys.getPublic())
                .build(new JcaContentSignerBuilder(alg).setProvider("BC").build(keys.getPrivate()));
        return PemUtils.toPem(csr);
    }
}
