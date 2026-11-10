package lt.vilniustech.itsm.mtls.auth;

import java.io.IOException;

import jakarta.servlet.http.HttpServletResponse;

import lt.vilniustech.itsm.mtls.web.ApiException;

/** Filters run before Spring MVC, so they write their JSON errors themselves. */
final class FilterErrors {

    private FilterErrors() {
    }

    static void write(HttpServletResponse response, ApiException e) throws IOException {
        response.setStatus(e.getStatus().value());
        response.setContentType("application/json");
        response.setHeader("Cache-Control", "no-store");
        response.getWriter().write("{\"error\":\"" + e.getCode() + "\",\"message\":\"" + e.getMessage() + "\"}");
    }
}
