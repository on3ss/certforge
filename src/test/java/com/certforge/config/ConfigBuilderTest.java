package com.certforge.config;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ConfigBuilderTest {

    @Test
    void shouldBuildConfigWithCustomValues() {
        Config config = Config.builder()
                .port(9000)
                .apiKeys(List.of("key1", "key2"))
                .sessionInactivityTimeout(1200)
                .sessionMaxLifetime(43200)
                .auditPath(Path.of("/var/log/audit.log"))
                .loggingLevel("debug")
                .build();

        assertEquals(9000, config.port());
        assertEquals(List.of("key1", "key2"), config.apiKeys());
        assertEquals(1200, config.sessionInactivityTimeout());
        assertEquals(43200, config.sessionMaxLifetime());
        assertEquals(Path.of("/var/log/audit.log"), config.auditPath());
        assertEquals("debug", config.loggingLevel());
        assertNotNull(config.poolConfig());
        assertNotNull(config.templateManager());
    }
}
