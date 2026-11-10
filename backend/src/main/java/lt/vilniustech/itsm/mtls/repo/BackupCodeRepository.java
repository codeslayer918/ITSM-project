package lt.vilniustech.itsm.mtls.repo;

import java.time.Instant;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import lt.vilniustech.itsm.mtls.domain.BackupCode;

public interface BackupCodeRepository extends JpaRepository<BackupCode, Long> {

    List<BackupCode> findByAccountIdAndUsedAtIsNull(Long accountId);

    long countByAccountIdAndUsedAtIsNull(Long accountId);

    @Modifying
    @Query("delete from BackupCode b where b.accountId = :accountId")
    int deleteAllForAccount(@Param("accountId") Long accountId);

    /** Atomic single-use consumption: returns 0 if another request already used the code. */
    @Modifying
    @Query("update BackupCode b set b.usedAt = :now where b.id = :id and b.usedAt is null")
    int markUsed(@Param("id") Long id, @Param("now") Instant now);
}
