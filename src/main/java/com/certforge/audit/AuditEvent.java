package com.certforge.audit;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

public class AuditEvent {

    private final Instant timestamp;
    private final AuditEventType type;
    private final Map<String, String> fields;

    public AuditEvent(AuditEventType type, Map<String, String> fields) {
        this.timestamp = Instant.now();
        this.type = type;
        this.fields = Collections.unmodifiableMap(new LinkedHashMap<>(fields));
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public AuditEventType getType() {
        return type;
    }

    public Map<String, String> getFields() {
        return fields;
    }

    public String toJson() {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"timestamp\":\"").append(timestamp.toString()).append("\",");
        sb.append("\"type\":\"").append(type.name()).append("\"");

        for (Map.Entry<String, String> entry : fields.entrySet()) {
            sb.append(",\"").append(escapeJson(entry.getKey())).append("\":\"")
                    .append(escapeJson(entry.getValue())).append("\"");
        }

        sb.append("}");
        return sb.toString();
    }

    private String escapeJson(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            switch (c) {
                case '\\' -> sb.append("\\\\");
                case '"' -> sb.append("\\\"");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString();
    }
}