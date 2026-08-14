package com.certforge.server;

import com.certforge.discovery.TokenInfo;
import com.certforge.session.CertificateInfo;

import java.time.Instant;
import java.util.List;

public final class JsonUtils {

    private JsonUtils() {
        // Utility class
    }

    public static String extractJsonValue(String json, String key) {
        if (json == null || key == null) return null;
        String searchKey = "\"" + key + "\"";
        int keyIndex = json.indexOf(searchKey);
        if (keyIndex < 0) return null;

        int colonIndex = json.indexOf(":", keyIndex + searchKey.length());
        if (colonIndex < 0) return null;

        int valueStart = colonIndex + 1;
        while (valueStart < json.length() && Character.isWhitespace(json.charAt(valueStart))) {
            valueStart++;
        }

        if (valueStart < json.length() && json.charAt(valueStart) == '"') {
            StringBuilder value = new StringBuilder();
            for (int i = valueStart + 1; i < json.length(); i++) {
                char c = json.charAt(i);
                if (c == '\\' && i + 1 < json.length()) {
                    value.append(json.charAt(i + 1));
                    i++;
                } else if (c == '"') {
                    return value.toString();
                } else {
                    value.append(c);
                }
            }
        }

        return null;
    }

    public static String escape(String s) {
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

    public static String buildTokensJson(List<TokenInfo> tokens) {
        StringBuilder json = new StringBuilder("{\"tokens\":[");
        for (int i = 0; i < tokens.size(); i++) {
            TokenInfo t = tokens.get(i);
            if (i > 0) json.append(",");
            json.append("{")
                    .append("\"id\":\"").append(escape(t.id())).append("\",")
                    .append("\"label\":\"").append(escape(t.label())).append("\",")
                    .append("\"manufacturer\":\"").append(escape(t.manufacturer())).append("\",")
                    .append("\"serial\":\"").append(escape(t.serial())).append("\",")
                    .append("\"libraryPath\":\"").append(escape(t.libraryPath())).append("\",")
                    .append("\"slotId\":").append(t.slotId())
                    .append("}");
        }
        json.append("]}");
        return json.toString();
    }

    public static String buildCertificatesJson(List<CertificateInfo> certs) {
        StringBuilder json = new StringBuilder("{\"certificates\":[");
        for (int i = 0; i < certs.size(); i++) {
            CertificateInfo c = certs.get(i);
            if (i > 0) json.append(",");
            json.append("{")
                    .append("\"alias\":\"").append(escape(c.alias())).append("\",")
                    .append("\"subject\":\"").append(escape(c.subject())).append("\",")
                    .append("\"issuer\":\"").append(escape(c.issuer())).append("\",")
                    .append("\"serialNumber\":\"").append(escape(c.serialNumber())).append("\",")
                    .append("\"notBefore\":\"").append(escape(c.notBefore())).append("\",")
                    .append("\"notAfter\":\"").append(escape(c.notAfter())).append("\",")
                    .append("\"keyType\":\"").append(escape(c.keyType())).append("\",")
                    .append("\"keySize\":").append(c.keySize())
                    .append("}");
        }
        json.append("]}");
        return json.toString();
    }

    public static String buildErrorJson(int statusCode, String errorCode, String message) {
        String timestamp = Instant.now().toString();
        return "{"
                + "\"error\":\"" + escape(errorCode) + "\","
                + "\"message\":\"" + escape(message) + "\","
                + "\"status\":" + statusCode + ","
                + "\"timestamp\":\"" + timestamp + "\""
                + "}";
    }
}
