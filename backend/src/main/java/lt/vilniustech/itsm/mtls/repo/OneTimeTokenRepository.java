package lt.vilniustech.itsm.mtls.repo;

import java.time.Instant;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import lt.vilniustech.itsm.mtls.domain.Account;
import lt.vilniustech.itsm.mtls.domain.OneTimeToken;

public interface OneTimeTokenRepository extends JpaRepository<OneTimeToken, Long> {

    @Query("select t from OneTimeToken t join fetch t.account where t.tokenHash = :hash")
    Optional<OneTimeToken> findByTokenHash(@Param("hash") String tokenHash);

    /** Atomic single-use consumption: returns 0 if the token was already used. */
    @Modifying
    @Query("update OneTimeToken t set t.usedAt = :now where t.id = :id and t.usedAt is null")
    int markUsed(@Param("id") Long id, @Param("now") Instant now);

    /** A new token of the same purpose supersedes the previous unused ones. */
    @Modifying
    @Query("update OneTimeToken t set t.usedAt = :now where t.account = :account and t.purpose = :purpose and t.usedAt is null")
    int invalidateUnused(@Param("account") Account account, @Param("purpose") OneTimeToken.Purpose purpose,
                         @Param("now") Instant now);

    @Modifying
    @Query("update OneTimeToken t set t.usedAt = :now where t.account = :account and t.usedAt is null")
    int invalidateAllUnused(@Param("account") Account account, @Param("now") Instant now);
}
