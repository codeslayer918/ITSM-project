package lt.vilniustech.itsm.mtls.pki;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import lt.vilniustech.itsm.mtls.config.AppProperties;

@Configuration
public class PkiConfig {

    @Bean
    public CertificateAuthority usersCertificateAuthority(AppProperties props) throws IOException {
        AppProperties.Pki pki = props.pki();
        X509Certificate caCert = PemUtils.parseCertificate(Files.readString(pki.usersCaCert(), StandardCharsets.US_ASCII));
        // The CA key is encrypted at rest; the passphrase comes from a Docker secret.
        char[] passphrase = Files.readString(pki.usersCaKeyPassphraseFile(), StandardCharsets.US_ASCII).trim().toCharArray();
        PrivateKey caKey = PemUtils.parsePrivateKey(Files.readString(pki.usersCaKey(), StandardCharsets.US_ASCII), passphrase);
        java.util.Arrays.fill(passphrase, '\0');
        return new CertificateAuthority(caCert, caKey, pki.organization(), pki.crlDistributionUrl());
    }
}
