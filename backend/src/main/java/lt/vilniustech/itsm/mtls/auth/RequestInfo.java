package lt.vilniustech.itsm.mtls.auth;

import jakarta.servlet.http.HttpServletRequest;

/** Request metadata recorded in the audit log. */
public record RequestInfo(String ip, String userAgent) {

    public static RequestInfo of(HttpServletRequest request) {
        // X-Real-IP is set by nginx (client values are overwritten), and only nginx can reach the backend.
        String ip = request.getHeader("X-Real-IP");
        if (ip == null || ip.isBlank()) {
            ip = request.getRemoteAddr();
        }
        String ua = request.getHeader("User-Agent");
        if (ua != null && ua.length() > 256) {
            ua = ua.substring(0, 256);
        }
        return new RequestInfo(ip, ua);
    }
}
