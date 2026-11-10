package lt.vilniustech.itsm.mtls.service;

import java.time.Duration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import lt.vilniustech.itsm.mtls.config.AppProperties;
import lt.vilniustech.itsm.mtls.domain.Account;
import lt.vilniustech.itsm.mtls.domain.OneTimeToken;
import lt.vilniustech.itsm.mtls.repo.AccountRepository;

/**
 * Creates the first administrator account on an empty database, with an enrolment token
 * taken from BOOTSTRAP_ADMIN_TOKEN (.env). The administrator then enrols exactly like any
 * other user: key pair generated locally, CSR, certificate with OU=admins.
 */
@Component
public class BootstrapAdmin implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(BootstrapAdmin.class);

    private final AccountRepository accounts;
    private final TokenService tokens;
    private final AppProperties props;

    public BootstrapAdmin(AccountRepository accounts, TokenService tokens, AppProperties props) {
        this.accounts = accounts;
        this.tokens = tokens;
        this.props = props;
    }

    @Override
    public void run(ApplicationArguments args) {
        AppProperties.Bootstrap bootstrap = props.bootstrap();
        if (accounts.existsByUsername(bootstrap.adminUsername())) {
            return;
        }
        Account admin = accounts.save(new Account(bootstrap.adminUsername(), bootstrap.adminEmail(), Account.ADMIN_GROUP));
        String token = bootstrap.adminToken();
        if (token == null || token.length() < 32) {
            token = tokens.issue(admin, OneTimeToken.Purpose.ENROLLMENT, Duration.ofHours(24));
            log.warn("BOOTSTRAP_ADMIN_TOKEN not set: generated enrolment token for '{}': {}", admin.getUsername(), token);
        } else {
            tokens.store(admin, OneTimeToken.Purpose.ENROLLMENT, token, Duration.ofHours(24));
            log.info("Bootstrap administrator '{}' created; enrol with BOOTSTRAP_ADMIN_TOKEN (scripts/enroll.sh).",
                    admin.getUsername());
        }
    }
}
