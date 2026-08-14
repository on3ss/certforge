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

    public static com.certforge.signing.appearance.SignatureAppearance parseAppearance(String json) {
        if (json == null) {
            return null;
        }

        String typeStr = extractJsonValue(json, "appearanceType");
        if (typeStr == null) {
            typeStr = extractJsonValue(json, "type");
        }
        if (typeStr == null && !json.contains("\"appearance\"")) {
            return null;
        }

        com.certforge.signing.appearance.SignatureAppearance.Type type = switch (typeStr != null ? typeStr.toUpperCase() : "TEXT") {
            case "NONE" -> com.certforge.signing.appearance.SignatureAppearance.Type.NONE;
            case "IMAGE" -> com.certforge.signing.appearance.SignatureAppearance.Type.IMAGE;
            case "TEXT_IMAGE", "TEXTIMAGE" -> com.certforge.signing.appearance.SignatureAppearance.Type.TEXT_IMAGE;
            default -> com.certforge.signing.appearance.SignatureAppearance.Type.TEXT;
        };

        String pageVal = extractJsonValue(json, "appearancePage");
        if (pageVal == null) pageVal = extractJsonValue(json, "page");
        int page = parseOrDefaultInt(pageVal, 0);

        String xVal = extractJsonValue(json, "appearanceX");
        if (xVal == null) xVal = extractJsonValue(json, "x");
        float x = parseOrDefaultFloat(xVal, 0f);

        String yVal = extractJsonValue(json, "appearanceY");
        if (yVal == null) yVal = extractJsonValue(json, "y");
        float y = parseOrDefaultFloat(yVal, 0f);

        String wVal = extractJsonValue(json, "appearanceWidth");
        if (wVal == null) wVal = extractJsonValue(json, "width");
        float width = parseOrDefaultFloat(wVal, 200f);

        String hVal = extractJsonValue(json, "appearanceHeight");
        if (hVal == null) hVal = extractJsonValue(json, "height");
        float height = parseOrDefaultFloat(hVal, 50f);

        String fsVal = extractJsonValue(json, "appearanceFontSize");
        if (fsVal == null) fsVal = extractJsonValue(json, "fontSize");
        float fontSize = parseOrDefaultFloat(fsVal, 10f);

        String pagePosStr = extractJsonValue(json, "appearancePosition");
        if (pagePosStr == null) {
            pagePosStr = extractJsonValue(json, "pagePosition");
        }
        com.certforge.signing.appearance.SignatureAppearance.PagePosition pagePos = pagePosStr != null
                ? com.certforge.signing.appearance.SignatureAppearance.PagePosition.fromString(pagePosStr)
                : null;

        String posTypeStr = extractJsonValue(json, "positionType");
        com.certforge.signing.appearance.SignatureAppearance.PositionType posType;
        if ("pagePosition".equalsIgnoreCase(posTypeStr) || pagePos != null) {
            posType = com.certforge.signing.appearance.SignatureAppearance.PositionType.PAGE_POSITION;
        } else {
            posType = com.certforge.signing.appearance.SignatureAppearance.PositionType.ABSOLUTE;
        }

        String imgBase64 = extractJsonValue(json, "appearanceImageBase64");
        byte[] imgData = null;
        if (imgBase64 != null && !imgBase64.isBlank()) {
            try {
                imgData = java.util.Base64.getDecoder().decode(imgBase64.trim());
            } catch (Exception _) {}
        }

        String reason = extractJsonValue(json, "reason");
        String location = extractJsonValue(json, "location");

        String searchText = extractJsonValue(json, "appearanceSearchText");
        if (searchText == null) {
            searchText = extractJsonValue(json, "searchText");
        }

        String searchPosStr = extractJsonValue(json, "appearanceSearchPosition");
        if (searchPosStr == null) {
            searchPosStr = extractJsonValue(json, "searchPosition");
        }
        com.certforge.signing.appearance.SignatureAppearance.SearchPosition searchPos =
                com.certforge.signing.appearance.SignatureAppearance.SearchPosition.fromString(searchPosStr);

        String paddingStr = extractJsonValue(json, "appearancePadding");
        if (paddingStr == null) {
            paddingStr = extractJsonValue(json, "padding");
        }
        float padding = parseOrDefaultFloat(paddingStr, 6f);

        return new com.certforge.signing.appearance.SignatureAppearance(
                type, posType, page, x, y, width, height, pagePos, null, fontSize, imgData, null, reason, location, searchText, searchPos, padding
        );
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
