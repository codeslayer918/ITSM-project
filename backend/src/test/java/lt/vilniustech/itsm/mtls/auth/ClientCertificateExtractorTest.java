package lt.vilniustech.itsm.mtls.auth;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class ClientCertificateExtractorTest {

    @Test
    void percentDecodingKeepsBase64PlusSigns() {
        // nginx $ssl_client_escaped_cert: newlines and '+' are percent-encoded, but a
        // literal '+' must never become a space.
        assertThat(ClientCertificateExtractor.percentDecode("-----BEGIN%20CERTIFICATE-----%0AMII%2Bab+c%0A"))
                .isEqualTo("-----BEGIN CERTIFICATE-----\nMII+ab+c\n");
    }
}
