package com.github.hackathon.advancedsecurityjava;

import static org.assertj.core.api.Assertions.assertThat;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.Appender;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.impl.Log4jLogEvent;
import org.apache.logging.log4j.core.layout.PatternLayout;
import org.apache.logging.log4j.message.SimpleMessage;
import org.junit.jupiter.api.Test;

class LogMaskingPatternTest {

    @Test
    void logPatternMasksSensitiveFields() {
        LoggerContext context = (LoggerContext) LogManager.getContext(false);
        Configuration configuration = context.getConfiguration();
        Appender appender = configuration.getAppender("Console");
        PatternLayout layout = (PatternLayout) appender.getLayout();

        LogEvent event = Log4jLogEvent.newBuilder()
                .setLoggerName("test")
                .setLevel(Level.INFO)
                .setMessage(new SimpleMessage(
                        "Authorization=Bearer abc password=secret payload={\"token\":\"abc123\"}"))
                .build();

        String output = layout.toSerializable(event);

        assertThat(output).contains("Authorization=***");
        assertThat(output).contains("password=***");
        assertThat(output).contains("\"token\":\"***\"");
        assertThat(output).doesNotContain("Bearer abc");
        assertThat(output).doesNotContain("secret");
        assertThat(output).doesNotContain("abc123");
    }
}
