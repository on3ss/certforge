package com.certforge.signing.appearance;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

public class SignatureAppearance {

    public enum Type {
        NONE, TEXT, IMAGE, TEXT_IMAGE
    }

    public enum PositionType {
        ABSOLUTE, PAGE_POSITION
    }

    public enum Position {
        TOP_LEFT, TOP_RIGHT, BOTTOM_LEFT, BOTTOM_RIGHT, CENTER;

        public static Position fromString(String str) {
            if (str == null || str.isBlank()) return null;
            return switch (str.trim().toLowerCase().replace("-", "_")) {
                case "top_left", "topleft" -> TOP_LEFT;
                case "top_right", "topright" -> TOP_RIGHT;
                case "bottom_left", "bottomleft" -> BOTTOM_LEFT;
                case "center" -> CENTER;
                case "bottom_right", "bottomright" -> BOTTOM_RIGHT;
                default -> null;
            };
        }
    }

    public enum PagePosition {
        TOP_LEFT, TOP_RIGHT, BOTTOM_LEFT, BOTTOM_RIGHT, CENTER;

        public static PagePosition fromString(String str) {
            if (str == null || str.isBlank()) return null;
            return switch (str.trim().toLowerCase().replace("_", "-")) {
                case "top-left", "topleft" -> TOP_LEFT;
                case "top-right", "topright" -> TOP_RIGHT;
                case "bottom-left", "bottomleft" -> BOTTOM_LEFT;
                case "center" -> CENTER;
                case "bottom-right", "bottomright" -> BOTTOM_RIGHT;
                default -> null;
            };
        }
    }

    public enum SearchPosition {
        ABOVE, BELOW, LEFT, RIGHT, OVER;

        public static SearchPosition fromString(String str) {
            if (str == null || str.isBlank()) return ABOVE;
            return switch (str.trim().toLowerCase().replace("_", "-")) {
                case "below" -> BELOW;
                case "left" -> LEFT;
                case "right" -> RIGHT;
                case "over", "overlay" -> OVER;
                default -> ABOVE;
            };
        }
    }

    private final Type type;
    private final PositionType positionType;
    private final int page;
    private final float x;
    private final float y;
    private final float width;
    private final float height;
    private final PagePosition pagePosition;
    private final List<String> textLines;
    private final float fontSize;
    private final byte[] imageData;
    private final String imagePath;
    private final String reason;
    private final String location;
    private final String searchText;
    private final SearchPosition searchPosition;
    private final float padding;

    public SignatureAppearance(Type type, PositionType positionType, int page,
                               float x, float y, float width, float height,
                               PagePosition pagePosition, List<String> textLines, float fontSize,
                               byte[] imageData, String imagePath, String reason, String location) {
        this(type, positionType, page, x, y, width, height, pagePosition, textLines, fontSize, imageData, imagePath, reason, location, null, SearchPosition.ABOVE, 6f);
    }

    public SignatureAppearance(Type type, PositionType positionType, int page,
                               float x, float y, float width, float height,
                               PagePosition pagePosition, List<String> textLines, float fontSize,
                               byte[] imageData, String imagePath, String reason, String location,
                               String searchText) {
        this(type, positionType, page, x, y, width, height, pagePosition, textLines, fontSize, imageData, imagePath, reason, location, searchText, SearchPosition.ABOVE, 6f);
    }

    public SignatureAppearance(Type type, PositionType positionType, int page,
                               float x, float y, float width, float height,
                               PagePosition pagePosition, List<String> textLines, float fontSize,
                               byte[] imageData, String imagePath, String reason, String location,
                               String searchText, SearchPosition searchPosition) {
        this(type, positionType, page, x, y, width, height, pagePosition, textLines, fontSize, imageData, imagePath, reason, location, searchText, searchPosition, 6f);
    }

    public SignatureAppearance(Type type, PositionType positionType, int page,
                               float x, float y, float width, float height,
                               PagePosition pagePosition, List<String> textLines, float fontSize,
                               byte[] imageData, String imagePath, String reason, String location,
                               String searchText, SearchPosition searchPosition, float padding) {
        this.type = type != null ? type : Type.NONE;
        this.positionType = positionType != null ? positionType : PositionType.ABSOLUTE;
        this.page = Math.max(0, page);
        this.x = x;
        this.y = y;
        this.width = width > 0 ? width : 200f;
        this.height = height > 0 ? height : 50f;
        this.pagePosition = pagePosition;
        this.textLines = textLines != null ? List.copyOf(textLines) : Collections.emptyList();
        this.fontSize = fontSize > 0 ? fontSize : 10f;
        this.imageData = imageData;
        this.imagePath = imagePath;
        this.reason = reason;
        this.location = location;
        this.searchText = searchText;
        this.searchPosition = searchPosition != null ? searchPosition : SearchPosition.ABOVE;
        this.padding = padding > 0 ? padding : 6f;
    }

    public Type type() { return type; }
    public PositionType positionType() { return positionType; }
    public int page() { return page; }
    public float x() { return x; }
    public float y() { return y; }
    public float width() { return width; }
    public float height() { return height; }
    public PagePosition pagePosition() { return pagePosition; }
    public List<String> textLines() { return textLines; }
    public float fontSize() { return fontSize; }
    public byte[] imageData() { return imageData; }
    public String imagePath() { return imagePath; }
    public String reason() { return reason; }
    public String location() { return location; }
    public String searchText() { return searchText; }
    public SearchPosition searchPosition() { return searchPosition; }
    public float padding() { return padding; }

    // Bean Getters for compatibility
    public Type getType() { return type(); }
    public PositionType getPositionType() { return positionType(); }
    public int getPage() { return page(); }
    public float getX() { return x(); }
    public float getY() { return y(); }
    public float getWidth() { return width(); }
    public float getHeight() { return height(); }
    public PagePosition getPagePosition() { return pagePosition(); }
    public Position getPosition() {
        if (pagePosition == null) return null;
        return switch (pagePosition) {
            case TOP_LEFT -> Position.TOP_LEFT;
            case TOP_RIGHT -> Position.TOP_RIGHT;
            case BOTTOM_LEFT -> Position.BOTTOM_LEFT;
            case CENTER -> Position.CENTER;
            case BOTTOM_RIGHT -> Position.BOTTOM_RIGHT;
        };
    }
    public List<String> getTextLines() { return textLines(); }
    public float getFontSize() { return fontSize(); }
    public byte[] getImageData() { return imageData(); }
    public String getImagePath() { return imagePath(); }
    public String getReason() { return reason(); }
    public String getLocation() { return location(); }
    public String getSearchText() { return searchText(); }
    public SearchPosition getSearchPosition() { return searchPosition(); }
    public float getPadding() { return padding(); }

    public boolean isVisible() {
        return type != null && type != Type.NONE;
    }

    public float[] calculateRectangle(float pageWidth, float pageHeight) {
        if (positionType == PositionType.ABSOLUTE) {
            return new float[] { x, y, width, height };
        }

        float margin = 36f; // 0.5 inch margin
        float calcX;
        float calcY;

        PagePosition pos = pagePosition != null ? pagePosition : PagePosition.BOTTOM_RIGHT;
        switch (pos) {
            case TOP_LEFT -> {
                calcX = margin;
                calcY = pageHeight - margin - height;
            }
            case TOP_RIGHT -> {
                calcX = pageWidth - margin - width;
                calcY = pageHeight - margin - height;
            }
            case BOTTOM_LEFT -> {
                calcX = margin;
                calcY = margin;
            }
            case CENTER -> {
                calcX = (pageWidth - width) / 2f;
                calcY = (pageHeight - height) / 2f;
            }
            case BOTTOM_RIGHT -> {
                calcX = pageWidth - margin - width;
                calcY = margin;
            }
            default -> {
                calcX = pageWidth - margin - width;
                calcY = margin;
            }
        }

        return new float[] { calcX, calcY, width, height };
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private Type type = Type.NONE;
        private PositionType positionType = PositionType.ABSOLUTE;
        private int page = 0;
        private float x = 0f;
        private float y = 0f;
        private float width = 200f;
        private float height = 50f;
        private PagePosition pagePosition = PagePosition.BOTTOM_RIGHT;
        private List<String> textLines = new ArrayList<>();
        private float fontSize = 10f;
        private byte[] imageData;
        private String imagePath;
        private String reason;
        private String location;
        private String searchText;
        private SearchPosition searchPosition = SearchPosition.ABOVE;
        private float padding = 6f;

        public Builder type(Type type) { this.type = type; return this; }
        public Builder positionType(PositionType positionType) { this.positionType = positionType; return this; }
        public Builder page(int page) { this.page = page; return this; }
        public Builder x(float x) { this.x = x; return this; }
        public Builder y(float y) { this.y = y; return this; }
        public Builder width(float width) { this.width = width; return this; }
        public Builder height(float height) { this.height = height; return this; }
        public Builder rectangle(float x, float y, float width, float height) {
            this.x = x; this.y = y; this.width = width; this.height = height; return this;
        }
        public Builder pagePosition(PagePosition pagePosition) { this.pagePosition = pagePosition; return this; }
        public Builder textLines(List<String> textLines) { this.textLines = textLines; return this; }
        public Builder fontSize(float fontSize) { this.fontSize = fontSize; return this; }
        public Builder imageData(byte[] imageData) { this.imageData = imageData; return this; }
        public Builder imagePath(String imagePath) { this.imagePath = imagePath; return this; }
        public Builder reason(String reason) { this.reason = reason; return this; }
        public Builder location(String location) { this.location = location; return this; }
        public Builder searchText(String searchText) { this.searchText = searchText; return this; }
        public Builder searchPosition(SearchPosition searchPosition) { this.searchPosition = searchPosition; return this; }
        public Builder searchPosition(String searchPositionStr) {
            this.searchPosition = SearchPosition.fromString(searchPositionStr);
            return this;
        }
        public Builder padding(float padding) { this.padding = padding; return this; }

        public SignatureAppearance build() {
            return new SignatureAppearance(type, positionType, page, x, y, width, height,
                    pagePosition, textLines, fontSize, imageData, imagePath, reason, location, searchText, searchPosition, padding);
        }
    }
}
