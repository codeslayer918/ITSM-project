package lt.vilniustech.itsm.mtls.service;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import lt.vilniustech.itsm.mtls.domain.Account;
import lt.vilniustech.itsm.mtls.domain.OneTimeToken;
import lt.vilniustech.itsm.mtls.pki.PemUtils;
import lt.vilniustech.itsm.mtls.repo.OneTimeTokenRepository;

/** Single-use, short-lived, random tokens (enrolment invitations and magic recovery links). */
@Service
public class TokenService {

    private final OneTimeTokenRepository tokens;
    private final SecureRandom random = new SecureRandom();

    public TokenService(OneTimeTokenRepository tokens) {
        this.tokens = tokens;
    }

    /** Creates a token and returns its clear value (shown or sent once, never stored). */
    @Transactional
    public String issue(Account account, OneTimeToken.Purpose purpose, Duration validity) {
        byte[] raw = new byte[32];
        random.nextBytes(raw);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        store(account, purpose, token, validity);
        return token;
    }

    /** Stores a token whose value was chosen elsewhere (bootstrap admin token from .env). */
    @Transactional
    public void store(Account account, OneTimeToken.Purpose purpose, String token, Duration validity) {
        Instant now = Instant.now();
        tokens.invalidateUnused(account, purpose, now);
        tokens.save(new OneTimeToken(account, purpose, hash(token), now.plus(validity)));
    }

    /**
     * Consumes a token atomically. Returns the account if the token exists, has the expected
     * purpose, has not expired and had not been used yet.
     */
    @Transactional
    public Optional<Account> consume(String token, OneTimeToken.Purpose purpose) {
        if (token == null || token.isBlank() || token.length() > 128) {
            return Optional.empty();
        }
        Instant now = Instant.now();
        return tokens.findByTokenHash(hash(token))
                .filter(t -> t.getPurpose() == purpose)
                .filter(t -> t.getUsedAt() == null && now.isBefore(t.getExpiresAt()))
                .filter(t -> tokens.markUsed(t.getId(), now) == 1)
                .map(OneTimeToken::getAccount);
    }

    @Transactional
    public void invalidateAll(Account account) {
        tokens.invalidateAllUnused(account, Instant.now());
    }

    static String hash(String token) {
        return PemUtils.sha256Hex(token.getBytes(StandardCharsets.UTF_8));
    }
}
