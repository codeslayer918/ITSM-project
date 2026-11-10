package lt.vilniustech.itsm.mtls.repo;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import lt.vilniustech.itsm.mtls.domain.AuditEvent;

public interface AuditEventRepository extends JpaRepository<AuditEvent, Long> {

    List<AuditEvent> findTop200ByOrderByOccurredAtDesc();
}
