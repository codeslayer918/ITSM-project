package lt.vilniustech.itsm.mtls.pki;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HexFormat;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;

public final class PemUtils {

    private PemUtils() {
    }

    public static X509Certificate parseCertificate(String pem) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(
                    new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
        } catch (CertificateException e) {
            throw new IllegalArgumentException("Not a valid X.509 certificate", e);
        }
    }

    /** Reads a PKCS#8 private key, encrypted ("ENCRYPTED PRIVATE KEY") or not. */
    public static PrivateKey parsePrivateKey(String pem, char[] passphrase) {
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            Object obj = parser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            if (obj instanceof PKCS8EncryptedPrivateKeyInfo encrypted) {
                PrivateKeyInfo info = encrypted.decryptPrivateKeyInfo(
                        new JceOpenSSLPKCS8DecryptorProviderBuilder().setProvider("BC").build(passphrase));
                return converter.getPrivateKey(info);
            }
            if (obj instanceof PrivateKeyInfo info) {
                return converter.getPrivateKey(info);
            }
            throw new IllegalArgumentException("Unsupported private key format");
        } catch (IOException | OperatorCreationException | PKCSException e) {
            throw new IllegalStateException("Cannot read the CA private key", e);
        }
    }

    public static String toPem(Object object) {
        StringWriter out = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(out)) {
            writer.writeObject(object);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return out.toString();
    }

    public static String sha256Hex(byte[] data) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** SHA-256 over the DER encoding: the fingerprint that maps a certificate to an account. */
    public static String fingerprint(X509Certificate cert) {
        try {
            return sha256Hex(cert.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    /** SHA-256 of the SubjectPublicKeyInfo: identifies the key pair independently of the certificate. */
    public static String spkiFingerprint(java.security.PublicKey key) {
        return sha256Hex(key.getEncoded());
    }

    /** Upper-case hexadecimal serial, the format nginx uses in $ssl_client_serial. */
    public static String serialHex(X509Certificate cert) {
        return cert.getSerialNumber().toString(16).toUpperCase();
    }

    /** Canonical form of a user-supplied serial ("0A1B", "a1b", "0x0a1b" -> "A1B"); null if not hex. */
    public static String normalizeSerial(String serial) {
        if (serial == null) {
            return null;
        }
        String hex = serial.trim().replaceFirst("^(?i)0x", "").replace(":", "");
        if (hex.isEmpty() || hex.length() > 64 || !hex.matches("[0-9A-Fa-f]+")) {
            return null;
        }
        return new java.math.BigInteger(hex, 16).toString(16).toUpperCase();
    }
}
