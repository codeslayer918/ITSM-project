package lt.vilniustech.itsm.mtls.repo;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import lt.vilniustech.itsm.mtls.domain.Account;

public interface AccountRepository extends JpaRepository<Account, Long> {

    Optional<Account> findByUsername(String username);

    Optional<Account> findByEmailIgnoreCase(String email);

    boolean existsByUsername(String username);

    boolean existsByEmailIgnoreCase(String email);

    List<Account> findByGroup(String group);

    List<Account> findAllByOrderByUsernameAsc();
}
