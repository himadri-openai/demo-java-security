package com.github.hackathon.advancedsecurityjava.filter;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

class RequestResponseLoggingFilterTest {

    @Test
    void formatHeadersForLogRedactsSensitiveHeaders() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer top-secret");
        request.addHeader("Cookie", "session=super-secret");
        request.addHeader("X-Request-Id", "abc-123");

        String formatted = RequestResponseLoggingFilter.formatHeadersForLog(request);

        assertThat(formatted).contains("Authorization=***");
        assertThat(formatted).contains("Cookie=***");
        assertThat(formatted).contains("X-Request-Id=abc-123");
        assertThat(formatted).doesNotContain("top-secret");
        assertThat(formatted).doesNotContain("super-secret");
    }
}
