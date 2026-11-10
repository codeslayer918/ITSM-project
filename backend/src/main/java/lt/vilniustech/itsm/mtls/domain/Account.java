package lt.vilniustech.itsm.mtls.domain;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "account")
public class Account {

    public static final String ADMIN_GROUP = "admins";

    public enum Role { USER, ADMIN }

    public enum Status { ACTIVE, DISABLED }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String username;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(name = "group_name", nullable = false)
    private String group;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Status status;

    @Column(name = "session_epoch", nullable = false)
    private int sessionEpoch;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    protected Account() {
    }

    public Account(String username, String email, String group) {
        this.username = username;
        this.email = email;
        this.group = group;
        // The role follows the group: only members of "admins" are administrators,
        // and their certificates carry OU=admins.
        this.role = ADMIN_GROUP.equals(group) ? Role.ADMIN : Role.USER;
        this.status = Status.ACTIVE;
        this.createdAt = Instant.now();
    }

    /** Invalidates every session created before this call (see SessionAuthFilter). */
    public void invalidateAllSessions() {
        sessionEpoch++;
    }

    public boolean isActive() {
        return status == Status.ACTIVE;
    }

    public boolean isAdmin() {
        return role == Role.ADMIN;
    }

    public Long getId() { return id; }
    public String getUsername() { return username; }
    public String getEmail() { return email; }
    public String getGroup() { return group; }
    public Role getRole() { return role; }
    public Status getStatus() { return status; }
    public void setStatus(Status status) { this.status = status; }
    public int getSessionEpoch() { return sessionEpoch; }
    public Instant getCreatedAt() { return createdAt; }
}
