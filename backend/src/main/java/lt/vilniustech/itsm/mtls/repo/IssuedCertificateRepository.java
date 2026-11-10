package lt.vilniustech.itsm.mtls.repo;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import lt.vilniustech.itsm.mtls.domain.Account;
import lt.vilniustech.itsm.mtls.domain.IssuedCertificate;

public interface IssuedCertificateRepository extends JpaRepository<IssuedCertificate, Long> {

    @Query("select c from IssuedCertificate c join fetch c.account where c.fingerprintSha256 = :fp")
    Optional<IssuedCertificate> findByFingerprintSha256(@org.springframework.data.repository.query.Param("fp") String fingerprintSha256);

    Optional<IssuedCertificate> findBySerialHex(String serialHex);

    List<IssuedCertificate> findByAccountOrderByCreatedAtDesc(Account account);

    List<IssuedCertificate> findByAccountAndStatus(Account account, IssuedCertificate.Status status);

    long countByAccountAndStatus(Account account, IssuedCertificate.Status status);

    List<IssuedCertificate> findByGroupAndStatus(String group, IssuedCertificate.Status status);

    List<IssuedCertificate> findByStatus(IssuedCertificate.Status status);

    boolean existsBySpkiSha256(String spkiSha256);

    @Query("select c from IssuedCertificate c join fetch c.account order by c.createdAt desc")
    List<IssuedCertificate> findAllWithAccount();
}
