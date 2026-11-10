package lt.vilniustech.itsm.mtls.auth;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;

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
 * First filter of the chain.
 * 1. Every request must carry the secret header injected by nginx: the X-SSL-Client-*
 *    headers are only trusted when they come from nginx (the backend port is not published,
 *    this is a second barrier).
 * 2. The request path must be canonical: no ';' (path parameters), no '%' (encoding), no '\',
 *    no empty, '.' or '..' segment. Spring MVC routes on a decoded path without path parameters,
 *    while the filters compare the raw URI; refusing any non-canonical path guarantees that both
 *    see the same path (e.g. "/api;x/admin/users" or "/api/%61dmin/users" would otherwise reach
 *    the admin controller without going through SessionAuthFilter). The application never
 *    builds such paths, so nothing legitimate is refused.
 * 3. Requests that arrived on the public listener (no client certificate) may only reach the
 *    enrolment, recovery and CRL endpoints.
 */
@Component
@Order(1)
public class ProxyGatewayFilter extends OncePerRequestFilter {

    private static final List<String> PUBLIC_PREFIXES = List.of(
            "/api/enroll", "/api/recovery/", "/crl/", "/ca/", "/assets/", "/enroll.html", "/recover.html");

    private final byte[] proxySecret;

    public ProxyGatewayFilter(AppProperties props) {
        if (props.proxySecret() == null || props.proxySecret().length() < 32) {
            throw new IllegalStateException("PROXY_SHARED_SECRET must be set (at least 32 characters)");
        }
        this.proxySecret = props.proxySecret().getBytes(StandardCharsets.UTF_8);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String provided = request.getHeader("X-Proxy-Secret");
        if (provided == null
                || !MessageDigest.isEqual(proxySecret, provided.getBytes(StandardCharsets.UTF_8))) {
            FilterErrors.write(response, ApiException.forbidden("direct_access_denied", "Requests must go through the TLS proxy."));
            return;
        }

        String path = request.getRequestURI();
        if (!isCanonical(path)) {
            FilterErrors.write(response, ApiException.badRequest("non_canonical_path", "Malformed request path."));
            return;
        }

        String listener = request.getHeader(ClientCertificateExtractor.HEADER_LISTENER);
        if (!ClientCertificateExtractor.LISTENER_MTLS.equals(listener)
                && PUBLIC_PREFIXES.stream().noneMatch(path::startsWith)) {
            FilterErrors.write(response, new ApiException(HttpStatus.NOT_FOUND, "not_found", "Not found."));
            return;
        }

        if (path.startsWith("/api/")) {
            response.setHeader("Cache-Control", "no-store");
        }
        chain.doFilter(request, response);
    }

    /** True if the raw path has exactly one interpretation (see point 2 of the class comment). */
    static boolean isCanonical(String path) {
        if (path == null || !path.startsWith("/")) {
            return false;
        }
        if (path.indexOf(';') >= 0 || path.indexOf('%') >= 0 || path.indexOf('\\') >= 0) {
            return false;
        }
        String[] segments = path.substring(1).split("/", -1);
        for (int i = 0; i < segments.length; i++) {
            String s = segments[i];
            boolean last = i == segments.length - 1;
            if ((s.isEmpty() && !last) || s.equals(".") || s.equals("..")) {
                return false;
            }
        }
        return true;
    }
}
