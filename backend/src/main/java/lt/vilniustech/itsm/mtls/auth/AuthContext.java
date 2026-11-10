package lt.vilniustech.itsm.mtls.auth;

import jakarta.servlet.http.HttpServletRequest;

import lt.vilniustech.itsm.mtls.web.ApiException;

/** Authenticated principal of the current request, set by SessionAuthFilter. */
public record AuthContext(
        Long accountId,
        String username,
        boolean admin,
        String certSerial,
        String certFingerprint,
        RequestInfo requestInfo) {

    public static final String REQUEST_ATTRIBUTE = AuthContext.class.getName();

    public static AuthContext require(HttpServletRequest request) {
        Object ctx = request.getAttribute(REQUEST_ATTRIBUTE);
        if (ctx instanceof AuthContext auth) {
            return auth;
        }
        throw ApiException.unauthorized("not_authenticated", "Authentication required.");
    }
}
