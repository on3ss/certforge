package com.certforge.config;

import org.yaml.snakeyaml.Yaml;

import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ConfigLoader {

    private static final Logger LOG = Logger.getLogger(ConfigLoader.class.getName());

    private static final int DEFAULT_PORT = 8443;
    private static final List<String> DEFAULT_API_KEYS = Collections.emptyList();
    private static final int DEFAULT_SESSION_INACTIVITY = 3600;
    private static final int DEFAULT_SESSION_MAX_LIFETIME = 86400;
    private static final Path DEFAULT_AUDIT_PATH = Path.of("audit.log");
    private static final String DEFAULT_LOGGING_LEVEL = "info";

    private static final Pattern ENV_PATTERN = Pattern.compile("\\$\\{([^}]+)}");

    public static Config load(Path configPath) throws Exception {
        return load(configPath, System::getenv);
    }

    static Config load(Path configPath, Function<String, String> resolver) throws Exception {
        LOG.fine(() -> "Loading configuration file from " + configPath);
        Map<String, Object> raw = parseYaml(configPath);
        raw = interpolate(raw, resolver);

        Map<String, Object> gw = getMap(raw, "gateway");
        int port = getInt(gw, "port", DEFAULT_PORT);
        List<String> apiKeys = getList(gw, "apiKeys", DEFAULT_API_KEYS);

        Map<String, Object> sessions = getMap(raw, "sessions");
        int inactivity = getInt(sessions, "inactivityTimeout", DEFAULT_SESSION_INACTIVITY);
        int maxLifetime = getInt(sessions, "maxLifetime", DEFAULT_SESSION_MAX_LIFETIME);

        Map<String, Object> audit = getMap(raw, "audit");
        String auditPathStr = getString(audit, "path", DEFAULT_AUDIT_PATH.toString());
        Path auditPath = Path.of(auditPathStr);

        Map<String, Object> logging = getMap(raw, "logging");
        String logLevel = getString(logging, "level", DEFAULT_LOGGING_LEVEL);

        Map<String, Object> poolMap = getMap(raw, "pool");
        com.certforge.pool.PoolConfig defaultPoolConfig = com.certforge.pool.PoolConfig.defaultConfig();
        int maxTotal = getInt(poolMap, "maxTotal", defaultPoolConfig.maxTotal());
        int maxIdle = getInt(poolMap, "maxIdle", defaultPoolConfig.maxIdle());
        int idleTimeout = getInt(poolMap, "idleTimeoutSeconds", defaultPoolConfig.idleTimeoutSeconds());
        int poolMaxLifetime = getInt(poolMap, "maxLifetimeSeconds", defaultPoolConfig.maxLifetimeSeconds());
        int valInterval = getInt(poolMap, "validationIntervalSeconds", defaultPoolConfig.validationIntervalSeconds());
        long borrowTimeout = getLong(poolMap, "borrowTimeoutMs", defaultPoolConfig.borrowTimeoutMs());

        com.certforge.pool.PoolConfig poolConfig = new com.certforge.pool.PoolConfig(
                maxTotal, maxIdle, idleTimeout, poolMaxLifetime, valInterval, borrowTimeout
        );

        String templatesDirStr = getString(raw, "templatesDir", "templates");
        Path templatesDir = Path.of(templatesDirStr);

        com.certforge.signing.appearance.TemplateManager templateManager = new com.certforge.signing.appearance.TemplateManager();
        Map<String, Object> templatesRaw = getMap(raw, "templates");
        for (Map.Entry<String, Object> entry : templatesRaw.entrySet()) {
            String name = entry.getKey();
            if (entry.getValue() instanceof Map<?, ?> tMap) {
                @SuppressWarnings("unchecked")
                Map<String, Object> map = (Map<String, Object>) tMap;

                String typeStr = getString(map, "type", "TEXT");
                com.certforge.signing.appearance.SignatureAppearance.Type type = switch (typeStr.toUpperCase()) {
                    case "NONE" -> com.certforge.signing.appearance.SignatureAppearance.Type.NONE;
                    case "IMAGE" -> com.certforge.signing.appearance.SignatureAppearance.Type.IMAGE;
                    case "TEXT_IMAGE", "TEXTIMAGE" -> com.certforge.signing.appearance.SignatureAppearance.Type.TEXT_IMAGE;
                    default -> com.certforge.signing.appearance.SignatureAppearance.Type.TEXT;
                };

                int page = getInt(map, "page", 0);
                Map<String, Object> rect = getMap(map, "rectangle");
                float x = getFloat(rect, "x", 0f);
                float y = getFloat(rect, "y", 0f);
                float width = getFloat(rect, "width", 200f);
                float height = getFloat(rect, "height", 50f);

                String pagePosStr = getString(map, "pagePosition", null);
                com.certforge.signing.appearance.SignatureAppearance.PagePosition pagePos = pagePosStr != null
                        ? com.certforge.signing.appearance.SignatureAppearance.PagePosition.fromString(pagePosStr)
                        : null;

                com.certforge.signing.appearance.SignatureAppearance.PositionType posType = pagePos != null
                        ? com.certforge.signing.appearance.SignatureAppearance.PositionType.PAGE_POSITION
                        : com.certforge.signing.appearance.SignatureAppearance.PositionType.ABSOLUTE;

                Map<String, Object> textMap = getMap(map, "text");
                List<String> lines = getList(textMap, "lines", Collections.emptyList());
                float fontSize = getFloat(textMap, "fontSize", 10f);

                Map<String, Object> imgMap = getMap(map, "image");
                String imgPath = getString(imgMap, "path", null);
                if (imgPath != null && !Path.of(imgPath).isAbsolute()) {
                    imgPath = templatesDir.resolve(imgPath).toString();
                }

                String reason = getString(map, "reason", null);
                String location = getString(map, "location", null);

                com.certforge.signing.appearance.SignatureAppearance app = new com.certforge.signing.appearance.SignatureAppearance(
                        type, posType, page, x, y, width, height, pagePos, lines, fontSize, null, imgPath, reason, location
                );

                templateManager.registerTemplate(new com.certforge.signing.appearance.TemplateDefinition(name, app));
            }
        }

        LOG.fine(() -> "Configuration parsed successfully: port=" + port + ", apiKeysCount=" + apiKeys.size() + ", logLevel=" + logLevel);
        return new Config(port, apiKeys, inactivity, maxLifetime, auditPath, logLevel, poolConfig, templateManager, templatesDir);
    }

    private static Map<String, Object> parseYaml(Path path) throws Exception {
        Yaml yaml = new Yaml();
        try (InputStream in = new FileInputStream(path.toFile())) {
            Map<String, Object> data = yaml.load(in);
            return data != null ? data : Collections.emptyMap();
        }
    }

    private static Map<String, Object> interpolate(Map<String, Object> map,
                                                   Function<String, String> resolver) {
        Map<String, Object> result = new HashMap<>();
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            Object value = entry.getValue();
            switch (value) {
                case String str -> result.put(entry.getKey(), interpolateString(str, resolver));
                case Map<?, ?> nestedMap -> {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> nested = (Map<String, Object>) nestedMap;
                    result.put(entry.getKey(), interpolate(nested, resolver));
                }
                case List<?> list -> {
                    List<Object> newList = new ArrayList<>();
                    for (Object item : list) {
                        if (item instanceof String s) {
                            newList.add(interpolateString(s, resolver));
                        } else {
                            newList.add(item);
                        }
                    }
                    result.put(entry.getKey(), newList);
                }
                default -> result.put(entry.getKey(), value);
            }
        }
        return result;
    }

    private static String interpolateString(String s, Function<String, String> resolver) {
        Matcher matcher = ENV_PATTERN.matcher(s);
        StringBuilder sb = new StringBuilder();
        while (matcher.find()) {
            String varName = matcher.group(1);
            String val = resolver.apply(varName);
            matcher.appendReplacement(sb, val != null ? Matcher.quoteReplacement(val) : matcher.group(0));
        }
        matcher.appendTail(sb);
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> getMap(Map<String, Object> parent, String key) {
        Object val = parent.get(key);
        if (val instanceof Map) {
            return (Map<String, Object>) val;
        }
        return Collections.emptyMap();
    }

    private static int getInt(Map<String, Object> map, String key, int defaultValue) {
        Object val = map.get(key);
        if (val instanceof Number number) {
            return number.intValue();
        } else if (val instanceof String str) {
            try {
                return Integer.parseInt(str);
            } catch (NumberFormatException _) {
            }
        }
        return defaultValue;
    }

    private static long getLong(Map<String, Object> map, String key, long defaultValue) {
        Object val = map.get(key);
        if (val instanceof Number number) {
            return number.longValue();
        } else if (val instanceof String str) {
            try {
                return Long.parseLong(str);
            } catch (NumberFormatException _) {
            }
        }
        return defaultValue;
    }

    private static float getFloat(Map<String, Object> map, String key, float defaultValue) {
        Object val = map.get(key);
        if (val instanceof Number number) {
            return number.floatValue();
        } else if (val instanceof String str) {
            try {
                return Float.parseFloat(str);
            } catch (NumberFormatException _) {
            }
        }
        return defaultValue;
    }

    @SuppressWarnings("unchecked")
    private static List<String> getList(Map<String, Object> map, String key, List<String> defaultValue) {
        Object val = map.get(key);
        if (val instanceof List) {
            return (List<String>) val;
        }
        return defaultValue;
    }

    private static String getString(Map<String, Object> map, String key, String defaultValue) {
        Object val = map.get(key);
        return val != null ? val.toString() : defaultValue;
    }
}