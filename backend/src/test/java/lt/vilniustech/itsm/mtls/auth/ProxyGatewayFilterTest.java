package lt.vilniustech.itsm.mtls.auth;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class ProxyGatewayFilterTest {

    @Test
    void normalPathsAreCanonical() {
        assertThat(ProxyGatewayFilter.isCanonical("/")).isTrue();
        assertThat(ProxyGatewayFilter.isCanonical("/api/admin/users")).isTrue();
        assertThat(ProxyGatewayFilter.isCanonical("/api/me/certificates/3A4F/revoke")).isTrue();
        assertThat(ProxyGatewayFilter.isCanonical("/assets/app.js")).isTrue();
        assertThat(ProxyGatewayFilter.isCanonical("/api/")).isTrue();
    }

    @Test
    void pathsThatSpringWouldReadDifferentlyAreRefused() {
        // Spring MVC drops ";..." path parameters and decodes "%61" before routing: these used to
        // reach the admin controller while SessionAuthFilter, matching the raw URI, skipped them.
        assertThat(ProxyGatewayFilter.isCanonical("/api;x/admin/users")).isFalse();
        assertThat(ProxyGatewayFilter.isCanonical("/api/admin;x/users")).isFalse();
        assertThat(ProxyGatewayFilter.isCanonical("/api/%61dmin/users")).isFalse();
        assertThat(ProxyGatewayFilter.isCanonical("//api/admin/users")).isFalse();
        assertThat(ProxyGatewayFilter.isCanonical("/api/./admin/users")).isFalse();
        assertThat(ProxyGatewayFilter.isCanonical("/assets/../api/admin/users")).isFalse();
        assertThat(ProxyGatewayFilter.isCanonical("/api/admin/..")).isFalse();
        assertThat(ProxyGatewayFilter.isCanonical("/api\\admin")).isFalse();
        assertThat(ProxyGatewayFilter.isCanonical("api/admin")).isFalse();
    }
}
