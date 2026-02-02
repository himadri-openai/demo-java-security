package com.github.hackathon.advancedsecurityjava.filter;

import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class RequestResponseLoggingFilter extends OncePerRequestFilter {

    private static final Logger logger = LogManager.getLogger(RequestResponseLoggingFilter.class);
    private static final Set<String> SENSITIVE_HEADERS = Set.of("authorization", "cookie", "set-cookie");

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        logger.info("Incoming request: method={} path={} headers={}",
                request.getMethod(), request.getRequestURI(), formatHeadersForLog(request));

        filterChain.doFilter(request, response);

        logger.info("Outgoing response: method={} path={} status={}",
                request.getMethod(), request.getRequestURI(), response.getStatus());
    }

    static String formatHeadersForLog(HttpServletRequest request) {
        Map<String, String> headerMap = new LinkedHashMap<>();
        Enumeration<String> headerNames = request.getHeaderNames();
        if (headerNames == null) {
            return "{}";
        }

        for (String headerName : Collections.list(headerNames)) {
            String value = request.getHeader(headerName);
            headerMap.put(headerName, maskHeaderValue(headerName, value));
        }

        return headerMap.entrySet().stream()
                .map(entry -> entry.getKey() + "=" + entry.getValue())
                .collect(Collectors.joining(", ", "{", "}"));
    }

    static String maskHeaderValue(String headerName, String value) {
        if (value == null) {
            return "";
        }
        String normalized = headerName == null ? "" : headerName.toLowerCase(Locale.ROOT);
        if (SENSITIVE_HEADERS.contains(normalized)) {
            return "***";
        }
        return value;
    }
}
