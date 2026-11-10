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

    /**
     * Same as {@link #require} and also checks the admin flag (role ADMIN and OU=admins).
     * Defence in depth: SessionAuthFilter already enforces it for /api/admin/**, but every admin
     * handler checks again, so a routing mismatch can never expose admin data.
     */
    public static AuthContext requireAdmin(HttpServletRequest request) {
        AuthContext auth = require(request);
        if (!auth.admin()) {
            throw ApiException.forbidden("admin_required", "An administrator certificate (OU=admins) is required.");
        }
        return auth;
    }
}
