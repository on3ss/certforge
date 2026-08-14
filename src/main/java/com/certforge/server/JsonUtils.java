package com.certforge.server;

import com.certforge.discovery.TokenInfo;
import com.certforge.session.CertificateInfo;
import com.certforge.signing.appearance.SignatureAppearance;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public final class JsonUtils {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private JsonUtils() {
    }

    public static ObjectMapper mapper() {
        return MAPPER;
    }

    public static String extractJsonValue(String json, String key) {
        if (json == null || key == null) return null;
        try {
            JsonNode root = MAPPER.readTree(json);
            JsonNode node = findNode(root, key);
            if (node != null && !node.isNull() && node.isValueNode()) {
                return node.asText();
            }
        } catch (Exception _) {
        }
        return null;
    }

    public static List<String> extractJsonStringList(String json, String key) {
        if (json == null || key == null) return null;
        try {
            JsonNode root = MAPPER.readTree(json);
            JsonNode arrayNode = findNode(root, key);
            if (arrayNode != null && arrayNode.isArray()) {
                List<String> list = new ArrayList<>();
                for (JsonNode item : arrayNode) {
                    list.add(item.asText());
                }
                return list;
            }
        } catch (Exception _) {
        }
        return null;
    }

    private static JsonNode findNode(JsonNode root, String key) {
        if (root == null || key == null) return null;
        if (root.has(key)) return root.get(key);
        if (root.has("appearance") && root.get("appearance").has(key)) {
            return root.get("appearance").get(key);
        }
        return null;
    }

    public static String escape(String s) {
        if (s == null) return "";
        try {
            return MAPPER.writeValueAsString(s).replaceAll("^\"|\"$", "");
        } catch (Exception _) {
            return s;
        }
    }

    public static String buildTokensJson(List<TokenInfo> tokens) {
        try {
            return MAPPER.writeValueAsString(java.util.Map.of("tokens", tokens));
        } catch (Exception e) {
            return "{\"tokens\":[]}";
        }
    }

    public static String buildCertificatesJson(List<CertificateInfo> certs) {
        try {
            return MAPPER.writeValueAsString(java.util.Map.of("certificates", certs));
        } catch (Exception e) {
            return "{\"certificates\":[]}";
        }
    }

    public static String buildErrorJson(int statusCode, String errorCode, String message) {
        String timestamp = Instant.now().toString();
        try {
            return MAPPER.writeValueAsString(java.util.Map.of(
                    "error", errorCode != null ? errorCode : "",
                    "message", message != null ? message : "",
                    "status", statusCode,
                    "timestamp", timestamp
            ));
        } catch (Exception e) {
            return "{\"error\":\"" + errorCode + "\",\"message\":\"" + message + "\",\"status\":" + statusCode + "}";
        }
    }

    public static SignatureAppearance parseAppearance(String json) {
        if (json == null || json.isBlank()) return null;
        try {
            JsonNode root = MAPPER.readTree(json);
            JsonNode appNode = root.has("appearance") ? root.get("appearance") : root;

            String typeStr = getText(root, appNode, "appearanceType", "type");
            if (typeStr == null && !root.has("appearance")) {
                return null;
            }

            SignatureAppearance.Type type = switch (typeStr != null ? typeStr.toUpperCase() : "TEXT") {
                case "NONE" -> SignatureAppearance.Type.NONE;
                case "IMAGE" -> SignatureAppearance.Type.IMAGE;
                case "TEXT_IMAGE", "TEXTIMAGE" -> SignatureAppearance.Type.TEXT_IMAGE;
                default -> SignatureAppearance.Type.TEXT;
            };

            int page = getInt(root, appNode, "appearancePage", "page", 0);
            float x = getFloat(root, appNode, "appearanceX", "x", 0f);
            float y = getFloat(root, appNode, "appearanceY", "y", 0f);
            float width = getFloat(root, appNode, "appearanceWidth", "width", 200f);
            float height = getFloat(root, appNode, "appearanceHeight", "height", 50f);
            float fontSize = getFloat(root, appNode, "appearanceFontSize", "fontSize", 10f);
            float padding = getFloat(root, appNode, "appearancePadding", "padding", 6f);

            JsonNode rectNode = (appNode != null && appNode.has("rectangle")) ? appNode.get("rectangle") : (root.has("rectangle") ? root.get("rectangle") : null);
            if (rectNode != null && rectNode.isObject()) {
                if (rectNode.has("x")) x = rectNode.get("x").floatValue();
                if (rectNode.has("y")) y = rectNode.get("y").floatValue();
                if (rectNode.has("width")) width = rectNode.get("width").floatValue();
                if (rectNode.has("height")) height = rectNode.get("height").floatValue();
            }

            String pagePosStr = getText(root, appNode, "appearancePosition", "pagePosition", "position", "pos");
            var pagePos = SignatureAppearance.PagePosition.fromString(pagePosStr);

            String posTypeStr = getText(root, appNode, "positionType", "typePosition");
            var posType = ("pagePosition".equalsIgnoreCase(posTypeStr) || pagePos != null)
                    ? SignatureAppearance.PositionType.PAGE_POSITION
                    : SignatureAppearance.PositionType.ABSOLUTE;

            String imgBase64 = getText(root, appNode, "appearanceImageBase64", "imageBase64");
            byte[] imgData = null;
            if (imgBase64 != null && !imgBase64.isBlank()) {
                try {
                    imgData = Base64.getDecoder().decode(imgBase64.trim());
                } catch (Exception _) {}
            }

            String reason = getText(root, appNode, "appearanceReason", "reason");
            String location = getText(root, appNode, "appearanceLocation", "location");
            String searchText = getText(root, appNode, "appearanceSearchText", "searchText");
            String searchPosStr = getText(root, appNode, "appearanceSearchPosition", "searchPosition");
            var searchPos = SignatureAppearance.SearchPosition.fromString(searchPosStr);

            List<String> textLines = getList(root, appNode, "appearanceTextLines", "textLines");

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
        } catch (Exception _) {
            return null;
        }
    }

    private static String getText(JsonNode root, JsonNode appNode, String... keys) {
        for (String k : keys) {
            if (appNode != null && appNode.has(k) && !appNode.get(k).isNull()) {
                return appNode.get(k).asText();
            }
            if (root != null && root.has(k) && !root.get(k).isNull()) {
                return root.get(k).asText();
            }
        }
        return null;
    }

    private static int getInt(JsonNode root, JsonNode appNode, String key1, String key2, int def) {
        String val = getText(root, appNode, key1, key2);
        if (val == null) return def;
        try { return Integer.parseInt(val); } catch (Exception _) { return def; }
    }

    private static float getFloat(JsonNode root, JsonNode appNode, String key1, String key2, float def) {
        String val = getText(root, appNode, key1, key2);
        if (val == null) return def;
        try { return Float.parseFloat(val); } catch (Exception _) { return def; }
    }

    private static List<String> getList(JsonNode root, JsonNode appNode, String key1, String key2) {
        for (String key : new String[]{key1, key2}) {
            JsonNode node = appNode != null && appNode.has(key) ? appNode.get(key) : (root != null && root.has(key) ? root.get(key) : null);
            if (node != null && node.isArray()) {
                List<String> list = new ArrayList<>();
                for (JsonNode item : node) {
                    list.add(item.asText());
                }
                return list;
            }
        }
        return null;
    }
}
