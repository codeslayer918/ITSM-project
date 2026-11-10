package lt.vilniustech.itsm.mtls.auth;

/** Attributes stored in the server-side HTTP session at login. */
public final class SessionKeys {

    public static final String ACCOUNT_ID = "auth.accountId";
    /** SHA-256 fingerprint of the certificate used to log in: the session is bound to it. */
    public static final String CERT_FINGERPRINT = "auth.certFingerprint";
    /** Account session epoch at login time; bumping the epoch kills every session. */
    public static final String EPOCH = "auth.epoch";
    public static final String LOGIN_AT = "auth.loginAt";

    private SessionKeys() {
    }
}
