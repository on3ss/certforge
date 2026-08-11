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

        assertEquals(9443, config.getPort());
        assertEquals(List.of("abc"), config.getApiKeys());
        assertEquals(3600, config.getSessionInactivityTimeout());
        assertEquals(86400, config.getSessionMaxLifetime());
        assertEquals("audit.log", config.getAuditPath().toString());
        assertEquals("info", config.getLoggingLevel());
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

        assertEquals(9999, config.getPort());
        assertEquals(List.of("secret123"), config.getApiKeys());
    }
}