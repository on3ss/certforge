package com.certforge.signing.appearance;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class SignatureAppearanceTest {

    @Test
    void testAbsoluteRectangleCalculation() {
        SignatureAppearance app = SignatureAppearance.builder()
                .type(SignatureAppearance.Type.TEXT)
                .positionType(SignatureAppearance.PositionType.ABSOLUTE)
                .x(100f)
                .y(150f)
                .width(200f)
                .height(60f)
                .build();

        float[] rect = app.calculateRectangle(612f, 792f); // Standard Letter page
        assertEquals(100f, rect[0]);
        assertEquals(150f, rect[1]);
        assertEquals(200f, rect[2]);
        assertEquals(60f, rect[3]);
    }

    @Test
    void testPagePositionTopLeftCalculation() {
        SignatureAppearance app = SignatureAppearance.builder()
                .type(SignatureAppearance.Type.TEXT)
                .positionType(SignatureAppearance.PositionType.PAGE_POSITION)
                .pagePosition(SignatureAppearance.PagePosition.TOP_LEFT)
                .width(200f)
                .height(50f)
                .build();

        float[] rect = app.calculateRectangle(612f, 792f);
        assertEquals(36f, rect[0]); // margin
        assertEquals(792f - 36f - 50f, rect[1]); // pageHeight - margin - height
        assertEquals(200f, rect[2]);
        assertEquals(50f, rect[3]);
    }

    @Test
    void testPagePositionBottomRightCalculation() {
        SignatureAppearance app = SignatureAppearance.builder()
                .type(SignatureAppearance.Type.TEXT)
                .positionType(SignatureAppearance.PositionType.PAGE_POSITION)
                .pagePosition(SignatureAppearance.PagePosition.BOTTOM_RIGHT)
                .width(200f)
                .height(50f)
                .build();

        float[] rect = app.calculateRectangle(612f, 792f);
        assertEquals(612f - 36f - 200f, rect[0]);
        assertEquals(36f, rect[1]);
        assertEquals(200f, rect[2]);
        assertEquals(50f, rect[3]);
    }

    @Test
    void testPagePositionCenterCalculation() {
        SignatureAppearance app = SignatureAppearance.builder()
                .type(SignatureAppearance.Type.TEXT)
                .positionType(SignatureAppearance.PositionType.PAGE_POSITION)
                .pagePosition(SignatureAppearance.PagePosition.CENTER)
                .width(200f)
                .height(100f)
                .build();

        float[] rect = app.calculateRectangle(600f, 800f);
        assertEquals(200f, rect[0]); // (600 - 200) / 2
        assertEquals(350f, rect[1]); // (800 - 100) / 2
    }

    @Test
    void testTemplateManagerPlaceholderSubstitution() {
        TemplateManager manager = new TemplateManager();
        SignatureAppearance base = SignatureAppearance.builder()
                .type(SignatureAppearance.Type.TEXT)
                .textLines(List.of("Signed by {signer}", "Date: {date}", "Reason: {reason}", "Location: {location}"))
                .reason("Approval")
                .location("HQ")
                .build();

        SignatureAppearance substituted = manager.substitutePlaceholders(base, "Alice Smith", "Security Audit", "Office A");
        assertNotNull(substituted);
        assertEquals("Security Audit", substituted.reason());
        assertEquals("Office A", substituted.location());

        List<String> lines = substituted.textLines();
        assertEquals(4, lines.size());
        assertTrue(lines.get(0).contains("Alice Smith"));
        assertFalse(lines.get(1).contains("{date}"));
        assertTrue(lines.get(2).contains("Security Audit"));
        assertTrue(lines.get(3).contains("Office A"));
    }

    @Test
    void testTemplateManagerMergeOverrides() {
        TemplateManager manager = new TemplateManager();
        SignatureAppearance base = SignatureAppearance.builder()
                .type(SignatureAppearance.Type.TEXT)
                .page(0)
                .width(200f)
                .height(50f)
                .reason("Base Reason")
                .build();

        SignatureAppearance override = SignatureAppearance.builder()
                .type(SignatureAppearance.Type.TEXT_IMAGE)
                .page(2)
                .reason("Override Reason")
                .build();

        SignatureAppearance merged = manager.merge(base, override);
        assertEquals(SignatureAppearance.Type.TEXT_IMAGE, merged.type());
        assertEquals(2, merged.page());
        assertEquals(200f, merged.width());
        assertEquals("Override Reason", merged.reason());
    }

    @Test
    void testVisualAppearanceStreamGeneration() throws Exception {
        SignatureAppearance appearance = SignatureAppearance.builder()
                .type(SignatureAppearance.Type.TEXT)
                .textLines(List.of("Digitally signed by CertForge", "Status: Verified"))
                .width(180f)
                .height(40f)
                .build();

        var inputStream = AppearanceStreamBuilder.buildVisualSignatureStream(appearance, 0f, 0f, 180f, 40f);
        assertNotNull(inputStream);
        byte[] bytes = inputStream.readAllBytes();
        assertTrue(bytes.length > 0, "Appearance stream must generate non-empty PDF bytes");
    }

    @Test
    void testSearchTextSupport() {
        SignatureAppearance app = SignatureAppearance.builder()
                .type(SignatureAppearance.Type.TEXT)
                .searchText("{{signature}}")
                .width(200f)
                .height(50f)
                .build();

        assertEquals("{{signature}}", app.searchText());
        assertEquals("{{signature}}", app.getSearchText());
        assertTrue(app.isVisible());
    }

    @Test
    void testTemplateManagerPreservesSearchTextWhenMergingWithStandardTemplate() {
        TemplateManager manager = new TemplateManager();

        SignatureAppearance override = SignatureAppearance.builder()
                .type(SignatureAppearance.Type.TEXT)
                .searchText("Treasury Officer")
                .width(200f)
                .height(45f)
                .textLines(List.of("Digitally Signed Here", "Status: Approved"))
                .build();

        SignatureAppearance resolved = manager.resolveAndMerge("standard", override, "rsaKey", "Approved", "HQ");
        assertNotNull(resolved);
        assertEquals("Treasury Officer", resolved.searchText());
        assertEquals("Treasury Officer", resolved.getSearchText());
    }
}
