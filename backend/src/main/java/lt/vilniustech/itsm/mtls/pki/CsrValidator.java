package lt.vilniustech.itsm.mtls.pki;

import java.io.IOException;
import java.io.StringReader;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.springframework.stereotype.Component;

import lt.vilniustech.itsm.mtls.web.ApiException;

/**
 * Validates a PKCS#10 CSR sent by a user. The CSR signature proves that the requester
 * holds the private key (proof of possession). Only strong key types are accepted.
 */
@Component
public class CsrValidator {

    private static final int MAX_PEM_LENGTH = 8192;
    private static final Set<ASN1ObjectIdentifier> ALLOWED_CURVES =
            Set.of(SECObjectIdentifiers.secp256r1, SECObjectIdentifiers.secp384r1);

    public PublicKey validateAndExtractKey(String pem) {
        if (pem == null || pem.isBlank() || pem.length() > MAX_PEM_LENGTH) {
            throw invalid("A PEM encoded CSR is required.");
        }
        PKCS10CertificationRequest csr;
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            Object obj = parser.readObject();
            if (!(obj instanceof PKCS10CertificationRequest request)) {
                throw invalid("The CSR is not a PKCS#10 certificate request.");
            }
            csr = request;
        } catch (IOException | RuntimeException e) {
            if (e instanceof ApiException api) {
                throw api;
            }
            throw invalid("The CSR could not be parsed.");
        }

        try {
            boolean popValid = csr.isSignatureValid(
                    new JcaContentVerifierProviderBuilder().setProvider("BC").build(csr.getSubjectPublicKeyInfo()));
            if (!popValid) {
                throw invalid("The CSR signature is invalid (proof of possession failed).");
            }
        } catch (ApiException e) {
            throw e;
        } catch (Exception e) {
            throw invalid("The CSR signature could not be verified.");
        }

        AlgorithmIdentifier keyAlg = csr.getSubjectPublicKeyInfo().getAlgorithm();
        PublicKey key;
        try {
            key = new JcaPKCS10CertificationRequest(csr).setProvider("BC").getPublicKey();
        } catch (Exception e) {
            throw invalid("Unsupported public key.");
        }
        if (X9ObjectIdentifiers.id_ecPublicKey.equals(keyAlg.getAlgorithm())) {
            if (!(keyAlg.getParameters() instanceof ASN1ObjectIdentifier curve) || !ALLOWED_CURVES.contains(curve)) {
                throw invalid("Only the named curves P-256 and P-384 are accepted.");
            }
        } else if (key instanceof RSAPublicKey rsa) {
            int bits = rsa.getModulus().bitLength();
            if (bits < 2048 || bits > 8192) {
                throw invalid("RSA keys must be between 2048 and 8192 bits.");
            }
        } else {
            throw invalid("Only EC (P-256, P-384) and RSA keys are accepted.");
        }
        return key;
    }

    private static ApiException invalid(String message) {
        return ApiException.badRequest("invalid_csr", message);
    }
}
