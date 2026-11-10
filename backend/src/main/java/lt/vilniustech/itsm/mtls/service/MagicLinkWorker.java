package lt.vilniustech.itsm.mtls.service;

import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import lt.vilniustech.itsm.mtls.auth.RequestInfo;
import lt.vilniustech.itsm.mtls.config.AppProperties;
import lt.vilniustech.itsm.mtls.domain.Account;
import lt.vilniustech.itsm.mtls.domain.OneTimeToken;
import lt.vilniustech.itsm.mtls.repo.AccountRepository;

/**
 * Does the account lookup, token creation and e-mail of a magic-link request in the
 * background. The HTTP response is sent before any of this work, so its timing is the same
 * whether the address belongs to an account or not (finding F2 of the security tests:
 * the synchronous version answered ~2x slower for existing accounts).
 */
@Service
public class MagicLinkWorker {

    private final AccountRepository accounts;
    private final TokenService tokens;
    private final NotificationService notifications;
    private final AuditService audit;
    private final AppProperties props;

    public MagicLinkWorker(AccountRepository accounts, TokenService tokens, NotificationService notifications,
                           AuditService audit, AppProperties props) {
        this.accounts = accounts;
        this.tokens = tokens;
        this.notifications = notifications;
        this.audit = audit;
        this.props = props;
    }

    @Async
    @Transactional
    public void process(String email, RequestInfo info) {
        Account account = accounts.findByEmailIgnoreCase(email).orElse(null);
        if (account == null || !account.isActive() || account.isAdmin()) {
            // No e-mail. Administrators must use a backup code (e-mail takeover != admin takeover).
            audit.record(AuditService.Type.RECOVERY_LINK_REQUESTED, AuditService.Outcome.FAILURE,
                    account == null ? null : account.getUsername(), info, null,
                    account == null ? "unknown e-mail" : "not eligible for e-mail recovery");
            return;
        }
        String token = tokens.issue(account, OneTimeToken.Purpose.MAGIC_LINK, props.tokens().magicLinkValidity());
        // The token is in the URL fragment: browsers never send it to the server nor in Referer.
        String link = props.publicBaseUrl() + "/recover.html#token=" + token;
        notifications.send(account.getEmail(), "Certificate recovery link",
                "A certificate reset was requested for '" + account.getUsername() + "' from IP " + info.ip() + ".\n\n"
                        + "Open this link within " + props.tokens().magicLinkValidity().toMinutes()
                        + " minutes (single use):\n" + link
                        + "\n\nCompleting the reset revokes all your current certificates.");
        audit.record(AuditService.Type.RECOVERY_LINK_REQUESTED, AuditService.Outcome.SUCCESS, account.getUsername(),
                info, null, "magic link sent");
    }
}
