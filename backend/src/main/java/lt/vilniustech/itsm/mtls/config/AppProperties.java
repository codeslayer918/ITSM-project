package lt.vilniustech.itsm.mtls.config;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("app")
public record AppProperties(
        String publicBaseUrl,
        List<String> allowedOrigins,
        String proxySecret,
        String mailFrom,
        Duration sessionAbsoluteTimeout,
        Pki pki,
        Tokens tokens,
        Bootstrap bootstrap,
        RateLimit rateLimit) {

    public record Pki(
            String organization,
            Path usersCaCert,
            Path usersCaKey,
            Path usersCaKeyPassphraseFile,
            Path usersCaChain,
            Path rootCaCrl,
            Path crlBundleOutput,
            String crlDistributionUrl,
            Duration clientCertValidity,
            Duration crlValidity,
            int maxActiveCertificates) {
    }

    public record Tokens(Duration enrollmentValidity, Duration magicLinkValidity) {
    }

    public record Bootstrap(String adminUsername, String adminEmail, String adminToken) {
    }

    public record RateLimit(
            int recoveryPerIp,
            int recoveryPerAccount,
            Duration recoveryWindow,
            int magicLinkPerEmail,
            Duration magicLinkWindow,
            int enrollPerIp,
            Duration enrollWindow) {
    }
}
