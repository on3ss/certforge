package com.certforge.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ConfigLoaderTest {

    @TempDir
    Path tempDir;

    @Test
    void shouldLoadMinimalValidConfig() throws Exception {
        String yaml = """
                gateway:
                  port: 9443
                  apiKeys:
                    - "abc"
                """;
        Path file = tempDir.resolve("gateway.yml");
        Files.writeString(file, yaml);

        Config config = ConfigLoader.load(file);

        assertEquals(9443, config.port());
        assertEquals(List.of("abc"), config.apiKeys());
        assertEquals(3600, config.sessionInactivityTimeout());
        assertEquals(86400, config.sessionMaxLifetime());
        assertEquals("audit.log", config.auditPath().toString());
        assertEquals("info", config.loggingLevel());
    }

    @Test
    void shouldUseDefaultsWhenConfigMissing() throws Exception {
        String yaml = "{}";
        Path file = tempDir.resolve("gateway.yml");
        Files.writeString(file, yaml);

        Config config = ConfigLoader.load(file);

        assertEquals(8443, config.port());
        assertTrue(config.apiKeys().isEmpty());
        assertEquals(3600, config.sessionInactivityTimeout());
        assertEquals(86400, config.sessionMaxLifetime());
    }

    @Test
    void shouldInterpolateEnvironmentVariables() throws Exception {
        String yaml = """
                gateway:
                  port: ${PORT}
                  apiKeys:
                    - ${API_KEY}
                """;
        Path file = tempDir.resolve("gateway.yml");
        Files.writeString(file, yaml);

        Config config = ConfigLoader.load(file, var -> switch (var) {
            case "PORT" -> "9999";
            case "API_KEY" -> "secret123";
            default -> null;
        });

        assertEquals(9999, config.port());
        assertEquals(List.of("secret123"), config.apiKeys());
    }

    @Test
    void shouldHandleInvalidPortValue() throws Exception {
        String yaml = """
                gateway:
                  port: not_a_number
                """;
        Path file = tempDir.resolve("gateway.yml");
        Files.writeString(file, yaml);

        Config config = ConfigLoader.load(file);
        assertEquals(8443, config.port()); // Falls back to default
    }

    @Test
    void shouldLoadPoolConfigFromYaml() throws Exception {
        String yaml = """
                pool:
                  maxTotal: 20
                  maxIdle: 8
                  idleTimeoutSeconds: 300
                  maxLifetimeSeconds: 1800
                  validationIntervalSeconds: 15
                  borrowTimeoutMs: 5000
                """;
        Path file = tempDir.resolve("gateway.yml");
        Files.writeString(file, yaml);

        Config config = ConfigLoader.load(file);
        assertNotNull(config.poolConfig());
        assertEquals(20, config.poolConfig().maxTotal());
        assertEquals(8, config.poolConfig().maxIdle());
        assertEquals(300, config.poolConfig().idleTimeoutSeconds());
        assertEquals(1800, config.poolConfig().maxLifetimeSeconds());
        assertEquals(15, config.poolConfig().validationIntervalSeconds());
        assertEquals(5000L, config.poolConfig().borrowTimeoutMs());
    }
}