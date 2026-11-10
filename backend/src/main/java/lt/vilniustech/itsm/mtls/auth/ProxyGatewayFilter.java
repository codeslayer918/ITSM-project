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
 * 2. Requests that arrived on the public listener (no client certificate) may only reach the
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

        String listener = request.getHeader(ClientCertificateExtractor.HEADER_LISTENER);
        String path = request.getRequestURI();
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
}
