package lt.vilniustech.itsm.mtls.domain;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "audit_event")
public class AuditEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "occurred_at", nullable = false)
    private Instant occurredAt;

    @Column(name = "event_type", nullable = false)
    private String eventType;

    @Column(nullable = false)
    private String outcome;

    private String username;

    @Column(name = "source_ip")
    private String sourceIp;

    @Column(name = "user_agent")
    private String userAgent;

    @Column(name = "cert_serial")
    private String certSerial;

    private String details;

    protected AuditEvent() {
    }

    public AuditEvent(String eventType, String outcome, String username, String sourceIp, String userAgent,
                      String certSerial, String details) {
        this.occurredAt = Instant.now();
        this.eventType = eventType;
        this.outcome = outcome;
        this.username = username;
        this.sourceIp = sourceIp;
        this.userAgent = userAgent;
        this.certSerial = certSerial;
        this.details = details;
    }

    public Long getId() { return id; }
    public Instant getOccurredAt() { return occurredAt; }
    public String getEventType() { return eventType; }
    public String getOutcome() { return outcome; }
    public String getUsername() { return username; }
    public String getSourceIp() { return sourceIp; }
    public String getUserAgent() { return userAgent; }
    public String getCertSerial() { return certSerial; }
    public String getDetails() { return details; }
}
