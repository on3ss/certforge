package com.certforge.signing.appearance;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

public class TemplateManager {

    private final Map<String, TemplateDefinition> templates = new ConcurrentHashMap<>();

    public TemplateManager() {
        this(Collections.emptyMap());
    }

    public TemplateManager(Map<String, TemplateDefinition> initialTemplates) {
        if (initialTemplates != null) {
            this.templates.putAll(initialTemplates);
        }
        if (!templates.containsKey("standard")) {
            templates.put("standard", new TemplateDefinition("standard", createStandardTemplate()));
        }
    }

    public void registerTemplate(TemplateDefinition template) {
        Objects.requireNonNull(template, "TemplateDefinition cannot be null");
        templates.put(template.name(), template);
    }

    public TemplateDefinition getTemplate(String name) {
        if (name == null) return null;
        return templates.get(name);
    }

    public boolean hasTemplate(String name) {
        return name != null && templates.containsKey(name);
    }

    public SignatureAppearance resolveAndMerge(String templateName, SignatureAppearance override,
                                              String signer, String reason, String location) {
        SignatureAppearance base = null;
        if (templateName != null && !templateName.isBlank()) {
            TemplateDefinition def = getTemplate(templateName);
            if (def == null) {
                throw new IllegalArgumentException("Signature template not found: " + templateName);
            }
            base = def.appearance();
        }

        SignatureAppearance merged = merge(base, override);
        if (merged == null) {
            return null;
        }

        return substitutePlaceholders(merged, signer, reason, location);
    }

    public SignatureAppearance merge(SignatureAppearance base, SignatureAppearance override) {
        if (base == null && override == null) return null;
        if (base == null) return override;
        if (override == null) return base;

        SignatureAppearance.Type type = override.type() != SignatureAppearance.Type.NONE
                ? override.type() : base.type();

        SignatureAppearance.PositionType posType = override.positionType() != null
                ? override.positionType() : base.positionType();

        int page = override.page() > 0 ? override.page() : base.page();

        float x = override.x() != 0f ? override.x() : base.x();
        float y = override.y() != 0f ? override.y() : base.y();
        float width = override.width() > 0f ? override.width() : base.width();
        float height = override.height() > 0f ? override.height() : base.height();

        SignatureAppearance.PagePosition pagePos = override.pagePosition() != null
                ? override.pagePosition() : base.pagePosition();

        List<String> lines = !override.textLines().isEmpty() ? override.textLines() : base.textLines();
        float fontSize = override.fontSize() > 0f ? override.fontSize() : base.fontSize();

        byte[] imgData = override.imageData() != null ? override.imageData() : base.imageData();
        String imgPath = override.imagePath() != null ? override.imagePath() : base.imagePath();

        String reason = override.reason() != null ? override.reason() : base.reason();
        String loc = override.location() != null ? override.location() : base.location();

        String searchText = (override.searchText() != null && !override.searchText().isBlank())
                ? override.searchText() : (base != null ? base.searchText() : null);

        SignatureAppearance.SearchPosition searchPos = override.searchPosition() != null
                ? override.searchPosition() : (base != null ? base.searchPosition() : SignatureAppearance.SearchPosition.ABOVE);

        float padding = override.padding() > 0 ? override.padding() : (base != null ? base.padding() : 6f);

        return SignatureAppearance.builder()
                .type(type)
                .positionType(posType)
                .page(page)
                .rectangle(x, y, width, height)
                .pagePosition(pagePos)
                .textLines(lines)
                .fontSize(fontSize)
                .imageData(imgData)
                .imagePath(imgPath)
                .reason(reason)
                .location(loc)
                .searchText(searchText)
                .searchPosition(searchPos)
                .padding(padding)
                .build();
    }

    public SignatureAppearance substitutePlaceholders(SignatureAppearance appearance, String signer,
                                                       String reason, String location) {
        if (appearance == null) return null;

        String dateStr = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z")
                .withZone(ZoneId.systemDefault())
                .format(Instant.now());

        String resolvedSigner = signer != null ? signer : "Unknown";
        String resolvedReason = reason != null ? reason : (appearance.reason() != null ? appearance.reason() : "");
        String resolvedLocation = location != null ? location : (appearance.location() != null ? appearance.location() : "");

        List<String> substitutedLines = new ArrayList<>();
        for (String line : appearance.textLines()) {
            String updated = line
                    .replace("{signer}", resolvedSigner)
                    .replace("{date}", dateStr)
                    .replace("{reason}", resolvedReason)
                    .replace("{location}", resolvedLocation);
            substitutedLines.add(updated);
        }

        return SignatureAppearance.builder()
                .type(appearance.type())
                .positionType(appearance.positionType())
                .page(appearance.page())
                .rectangle(appearance.x(), appearance.y(), appearance.width(), appearance.height())
                .pagePosition(appearance.pagePosition())
                .textLines(substitutedLines)
                .fontSize(appearance.fontSize())
                .imageData(appearance.imageData())
                .imagePath(appearance.imagePath())
                .reason(resolvedReason)
                .location(resolvedLocation)
                .searchText(appearance.searchText())
                .searchPosition(appearance.searchPosition())
                .padding(appearance.padding())
                .build();
    }

    private static SignatureAppearance createStandardTemplate() {
        return SignatureAppearance.builder()
                .type(SignatureAppearance.Type.TEXT)
                .positionType(SignatureAppearance.PositionType.PAGE_POSITION)
                .pagePosition(SignatureAppearance.PagePosition.BOTTOM_RIGHT)
                .width(220f)
                .height(45f)
                .fontSize(9f)
                .textLines(List.of("Digitally signed by {signer}", "Date: {date}", "Reason: {reason}"))
                .reason("Document Approval")
                .location("CertForge Gateway")
                .build();
    }
}
