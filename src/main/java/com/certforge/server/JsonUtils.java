package com.certforge.server;

import com.certforge.discovery.TokenInfo;
import com.certforge.session.CertificateInfo;
import com.certforge.signing.appearance.SignatureAppearance;

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

    public static List<String> extractJsonStringList(String json, String key) {
        if (json == null || key == null) return null;
        String searchKey = "\"" + key + "\"";
        int keyIndex = json.indexOf(searchKey);
        if (keyIndex < 0) return null;

        int bracketStart = json.indexOf("[", keyIndex + searchKey.length());
        if (bracketStart < 0) return null;

        int bracketEnd = json.indexOf("]", bracketStart);
        if (bracketEnd < 0) return null;

        String arrayContent = json.substring(bracketStart + 1, bracketEnd);
        List<String> list = new java.util.ArrayList<>();
        boolean inQuotes = false;
        StringBuilder current = new StringBuilder();

        for (int i = 0; i < arrayContent.length(); i++) {
            char c = arrayContent.charAt(i);
            if (c == '\\' && i + 1 < arrayContent.length()) {
                current.append(arrayContent.charAt(i + 1));
                i++;
            } else if (c == '"') {
                if (inQuotes) {
                    list.add(current.toString());
                    current.setLength(0);
                    inQuotes = false;
                } else {
                    inQuotes = true;
                }
            } else if (inQuotes) {
                current.append(c);
            }
        }
        return list;
    }

    private static String extractValue(String json, String primaryKey, String secondaryKey) {
        String val = extractJsonValue(json, primaryKey);
        if (val == null && secondaryKey != null) {
            val = extractJsonValue(json, secondaryKey);
        }
        return val;
    }

    public static com.certforge.signing.appearance.SignatureAppearance parseAppearance(String json) {
        if (json == null) {
            return null;
        }

        String typeStr = extractValue(json, "appearanceType", "type");
        if (typeStr == null && !json.contains("\"appearance\"")) {
            return null;
        }

        com.certforge.signing.appearance.SignatureAppearance.Type type = switch (typeStr != null ? typeStr.toUpperCase() : "TEXT") {
            case "NONE" -> com.certforge.signing.appearance.SignatureAppearance.Type.NONE;
            case "IMAGE" -> com.certforge.signing.appearance.SignatureAppearance.Type.IMAGE;
            case "TEXT_IMAGE", "TEXTIMAGE" -> com.certforge.signing.appearance.SignatureAppearance.Type.TEXT_IMAGE;
            default -> com.certforge.signing.appearance.SignatureAppearance.Type.TEXT;
        };

        int page = parseOrDefaultInt(extractValue(json, "appearancePage", "page"), 0);
        float x = parseOrDefaultFloat(extractValue(json, "appearanceX", "x"), 0f);
        float y = parseOrDefaultFloat(extractValue(json, "appearanceY", "y"), 0f);
        float width = parseOrDefaultFloat(extractValue(json, "appearanceWidth", "width"), 200f);
        float height = parseOrDefaultFloat(extractValue(json, "appearanceHeight", "height"), 50f);
        float fontSize = parseOrDefaultFloat(extractValue(json, "appearanceFontSize", "fontSize"), 10f);
        float padding = parseOrDefaultFloat(extractValue(json, "appearancePadding", "padding"), 6f);

        String pagePosStr = extractValue(json, "appearancePosition", "pagePosition");
        if (pagePosStr == null) {
            pagePosStr = extractValue(json, "position", "pos");
        }
        var pagePos = com.certforge.signing.appearance.SignatureAppearance.PagePosition.fromString(pagePosStr);

        String posTypeStr = extractValue(json, "positionType", "typePosition");
        var posType = ("pagePosition".equalsIgnoreCase(posTypeStr) || pagePos != null)
                ? com.certforge.signing.appearance.SignatureAppearance.PositionType.PAGE_POSITION
                : com.certforge.signing.appearance.SignatureAppearance.PositionType.ABSOLUTE;

        String imgBase64 = extractValue(json, "appearanceImageBase64", "imageBase64");
        byte[] imgData = null;
        if (imgBase64 != null && !imgBase64.isBlank()) {
            try {
                imgData = java.util.Base64.getDecoder().decode(imgBase64.trim());
            } catch (Exception _) {}
        }

        String reason = extractValue(json, "appearanceReason", "reason");
        String location = extractValue(json, "appearanceLocation", "location");
        String searchText = extractValue(json, "appearanceSearchText", "searchText");
        String searchPosStr = extractValue(json, "appearanceSearchPosition", "searchPosition");
        var searchPos = com.certforge.signing.appearance.SignatureAppearance.SearchPosition.fromString(searchPosStr);

        List<String> textLines = extractJsonStringList(json, "appearanceTextLines");
        if (textLines == null) {
            textLines = extractJsonStringList(json, "textLines");
        }

        return SignatureAppearance.builder()
                .type(type)
                .positionType(posType)
                .page(page)
                .rectangle(x, y, width, height)
                .pagePosition(pagePos)
                .textLines(textLines)
                .fontSize(fontSize)
                .imageData(imgData)
                .reason(reason)
                .location(location)
                .searchText(searchText)
                .searchPosition(searchPos)
                .padding(padding)
                .build();
    }

    private static int parseOrDefaultInt(String str, int def) {
        if (str == null) return def;
        try {
            return Integer.parseInt(str.trim());
        } catch (NumberFormatException _) {
            return def;
        }
    }

    private static float parseOrDefaultFloat(String str, float def) {
        if (str == null) return def;
        try {
            return Float.parseFloat(str.trim());
        } catch (NumberFormatException _) {
            return def;
        }
    }
}
