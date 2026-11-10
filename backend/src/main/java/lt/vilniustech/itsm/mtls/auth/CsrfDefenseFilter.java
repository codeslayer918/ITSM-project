package lt.vilniustech.itsm.mtls.auth;

import java.io.IOException;
import java.util.Set;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import lt.vilniustech.itsm.mtls.config.AppProperties;
import lt.vilniustech.itsm.mtls.web.ApiException;

/**
 * CSRF defence for state-changing requests, in addition to the SameSite=Strict cookie.
 * Browsers attach client certificates to cross-site requests, so the certificate alone
 * must not be enough to change state:
 *  - Sec-Fetch-Site: cross-site is rejected,
 *  - an Origin header, if present, must be one of ours,
 *  - the body must be application/json, which a cross-site HTML form cannot send without
 *    a CORS preflight (and CORS is not enabled).
 */
@Component
@Order(2)
public class CsrfDefenseFilter extends OncePerRequestFilter {

    private static final Set<String> SAFE_METHODS = Set.of("GET", "HEAD", "OPTIONS");

    private final Set<String> allowedOrigins;

    public CsrfDefenseFilter(AppProperties props) {
        this.allowedOrigins = Set.copyOf(props.allowedOrigins());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (!SAFE_METHODS.contains(request.getMethod())) {
            if ("cross-site".equalsIgnoreCase(request.getHeader("Sec-Fetch-Site"))) {
                FilterErrors.write(response, ApiException.forbidden("cross_site_request", "Cross-site requests are not allowed."));
                return;
            }
            String origin = request.getHeader("Origin");
            if (origin != null && !allowedOrigins.contains(origin)) {
                FilterErrors.write(response, ApiException.forbidden("bad_origin", "Origin not allowed."));
                return;
            }
            String contentType = request.getContentType();
            if (contentType == null || !contentType.toLowerCase().startsWith("application/json")) {
                FilterErrors.write(response, new ApiException(HttpStatus.UNSUPPORTED_MEDIA_TYPE,
                        "unsupported_media_type", "Use Content-Type: application/json."));
                return;
            }
        }
        chain.doFilter(request, response);
    }
}
