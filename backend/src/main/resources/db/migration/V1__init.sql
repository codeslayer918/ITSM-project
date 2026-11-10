-- Accounts. The group is copied into the OU of every certificate issued to the account.
create table account (
    id             bigint generated always as identity primary key,
    username       varchar(32)  not null unique,
    email          varchar(254) not null unique,
    group_name     varchar(32)  not null,
    role           varchar(16)  not null,
    status         varchar(16)  not null,
    -- Incremented to invalidate every existing session of the account at once.
    session_epoch  integer      not null default 0,
    created_at     timestamptz  not null
);

-- Every certificate ever issued by the Users CA (through the backend).
-- This table is both the fingerprint -> account mapping and the application-level
-- revocation list that is checked on every request.
create table issued_certificate (
    id                  bigint generated always as identity primary key,
    account_id          bigint       not null references account (id),
    serial_hex          varchar(64)  not null unique,
    fingerprint_sha256  varchar(64)  not null unique,
    spki_sha256         varchar(64)  not null,
    subject_dn          varchar(512) not null,
    group_name          varchar(32)  not null,
    device_label        varchar(64)  not null,
    issued_via          varchar(32)  not null,
    not_before          timestamptz  not null,
    not_after           timestamptz  not null,
    status              varchar(16)  not null,
    revoked_at          timestamptz,
    revocation_reason   varchar(32),
    created_at          timestamptz  not null
);
create index idx_cert_account on issued_certificate (account_id);
create index idx_cert_group on issued_certificate (group_name);
create index idx_cert_status on issued_certificate (status);
create index idx_cert_spki on issued_certificate (spki_sha256);

-- One-time backup codes (Argon2id hashes). They can only enrol a new certificate.
create table backup_code (
    id          bigint generated always as identity primary key,
    account_id  bigint       not null references account (id),
    code_hash   varchar(255) not null,
    used_at     timestamptz,
    created_at  timestamptz  not null
);
create index idx_backup_code_account on backup_code (account_id);

-- Single-use tokens (enrolment invitations and magic recovery links).
-- Only the SHA-256 of the token is stored.
create table one_time_token (
    id          bigint generated always as identity primary key,
    account_id  bigint      not null references account (id),
    purpose     varchar(32) not null,
    token_hash  varchar(64) not null unique,
    expires_at  timestamptz not null,
    used_at     timestamptz,
    created_at  timestamptz not null
);
create index idx_token_account on one_time_token (account_id);

-- Security audit trail (never contains codes, tokens or session ids).
create table audit_event (
    id           bigint generated always as identity primary key,
    occurred_at  timestamptz   not null,
    event_type   varchar(48)   not null,
    outcome      varchar(16)   not null,
    username     varchar(64),
    source_ip    varchar(64),
    user_agent   varchar(256),
    cert_serial  varchar(64),
    details      varchar(1024)
);
create index idx_audit_time on audit_event (occurred_at desc);

-- Monotonic CRL number (RFC 5280 section 5.2.3).
create table crl_state (
    id          integer primary key,
    crl_number  bigint not null
);
insert into crl_state (id, crl_number) values (1, 0);
