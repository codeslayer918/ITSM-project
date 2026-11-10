package lt.vilniustech.itsm.mtls.service;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import lt.vilniustech.itsm.mtls.domain.Account;
import lt.vilniustech.itsm.mtls.domain.BackupCode;
import lt.vilniustech.itsm.mtls.repo.BackupCodeRepository;

/**
 * Ten one-time backup codes per account, stored as Argon2id hashes.
 * A backup code can only be used to enrol a new certificate (account recovery),
 * never to log in: login always requires a client certificate.
 */
@Service
public class BackupCodeService {

    public static final int CODE_COUNT = 10;
    /** Crockford-like alphabet without 0/O/1/I/L to avoid transcription errors. */
    private static final char[] ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ".toCharArray();
    private static final int CODE_LENGTH = 10; // 10 symbols * log2(31) ~ 49.5 bits of entropy

    // OWASP Password Storage Cheat Sheet: Argon2id, m=19 MiB, t=2, p=1.
    private final Argon2PasswordEncoder encoder = new Argon2PasswordEncoder(16, 32, 1, 19 * 1024, 2);
    private final String dummyHash = encoder.encode("dummy-code-used-for-constant-work");
    private final BackupCodeRepository repository;
    private final SecureRandom random = new SecureRandom();

    public BackupCodeService(BackupCodeRepository repository) {
        this.repository = repository;
    }

    /** Replaces every existing code of the account; returns the clear codes (displayed once). */
    @Transactional
    public List<String> regenerate(Account account) {
        repository.deleteAllForAccount(account.getId());
        List<String> codes = new ArrayList<>(CODE_COUNT);
        for (int i = 0; i < CODE_COUNT; i++) {
            String code = randomCode();
            codes.add(code.substring(0, 5) + "-" + code.substring(5));
            repository.save(new BackupCode(account.getId(), encoder.encode(code)));
        }
        return codes;
    }

    @Transactional
    public void deleteAll(Account account) {
        repository.deleteAllForAccount(account.getId());
    }

    public long remaining(Account account) {
        return repository.countByAccountIdAndUsedAtIsNull(account.getId());
    }

    /**
     * Verifies a code and consumes it atomically. The same amount of Argon2 work is done
     * whether the account exists or not, and whatever the number of remaining codes,
     * so the response time does not reveal which usernames exist.
     */
    @Transactional
    public boolean verifyAndConsume(Account accountOrNull, String submittedCode) {
        String normalized = normalize(submittedCode);
        List<BackupCode> candidates = accountOrNull == null
                ? List.of()
                : repository.findByAccountIdAndUsedAtIsNull(accountOrNull.getId());
        BackupCode match = null;
        for (int i = 0; i < CODE_COUNT; i++) {
            if (i < candidates.size()) {
                if (encoder.matches(normalized, candidates.get(i).getCodeHash()) && match == null) {
                    match = candidates.get(i);
                }
            } else {
                encoder.matches(normalized, dummyHash);
            }
        }
        return match != null && repository.markUsed(match.getId(), Instant.now()) == 1;
    }

    static String normalize(String code) {
        if (code == null) {
            return "";
        }
        String normalized = code.toUpperCase().replaceAll("[^A-Z0-9]", "");
        return normalized.length() > 32 ? normalized.substring(0, 32) : normalized;
    }

    private String randomCode() {
        char[] chars = new char[CODE_LENGTH];
        for (int i = 0; i < CODE_LENGTH; i++) {
            chars[i] = ALPHABET[random.nextInt(ALPHABET.length)];
        }
        return new String(chars);
    }
}
