package com.certforge.signing.appearance;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.logging.Logger;

public class AppearanceStreamBuilder {

    private static final Logger LOG = Logger.getLogger(AppearanceStreamBuilder.class.getName());

    public static InputStream buildVisualSignatureStream(SignatureAppearance appearance, float x, float y, float width, float height)
            throws Exception {
        if (appearance == null || appearance.type() == SignatureAppearance.Type.NONE) {
            return null;
        }

        try (PDDocument doc = new PDDocument()) {
            PDPage page = new PDPage(new PDRectangle(x + width, y + height));
            doc.addPage(page);

            org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm acroForm = new org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm(doc);
            doc.getDocumentCatalog().setAcroForm(acroForm);

            org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField signatureField = new org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField(acroForm);
            signatureField.setPartialName("Signature1");
            acroForm.getFields().add(signatureField);

            org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget widget = signatureField.getWidgets().get(0);
            widget.setRectangle(new PDRectangle(x, y, width, height));
            widget.setPage(page);

            org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceDictionary appearanceDictionary = new org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceDictionary();
            org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceStream appearanceStream = new org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceStream(doc);
            appearanceStream.setBBox(new PDRectangle(width, height));
            appearanceStream.setResources(new org.apache.pdfbox.pdmodel.PDResources());

            float pad = appearance.padding() > 0 ? appearance.padding() : 6f;
            PDFont font = new PDType1Font(Standard14Fonts.FontName.HELVETICA);
            float fontSize = appearance.fontSize() > 0 ? appearance.fontSize() : 10f;
            float leading = fontSize * 1.2f;

            byte[] imgBytes = resolveImageBytes(appearance);

            try (PDPageContentStream cs = new PDPageContentStream(doc, appearanceStream)) {
                // Light border around signature box for visual clarity
                cs.setLineWidth(0.5f);
                cs.setStrokingColor(0.7f, 0.7f, 0.7f);
                cs.addRect(0.5f, 0.5f, width - 1f, height - 1f);
                cs.stroke();

                SignatureAppearance.Type type = appearance.type();

                if (type == SignatureAppearance.Type.IMAGE && imgBytes != null) {
                    PDImageXObject img = PDImageXObject.createFromByteArray(doc, imgBytes, "signature-image");
                    cs.drawImage(img, pad, pad, width - (pad * 2f), height - (pad * 2f));

                } else if (type == SignatureAppearance.Type.TEXT_IMAGE && imgBytes != null) {
                    float imgWidth = Math.min(width * 0.35f, height - (pad * 2f));
                    PDImageXObject img = PDImageXObject.createFromByteArray(doc, imgBytes, "signature-image");
                    cs.drawImage(img, pad, (height - imgWidth) / 2f, imgWidth, imgWidth);

                    float textX = pad + imgWidth + 8f;
                    renderText(cs, font, fontSize, leading, textX, pad, height, appearance.textLines());

                } else if (type == SignatureAppearance.Type.TEXT || type == SignatureAppearance.Type.TEXT_IMAGE) {
                    renderText(cs, font, fontSize, leading, pad + 2f, pad, height, appearance.textLines());
                }
            }

            appearanceDictionary.setNormalAppearance(appearanceStream);
            widget.setAppearance(appearanceDictionary);

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            doc.save(baos);
            LOG.fine(() -> "Generated visual signature appearance stream: " + baos.size() + " bytes");
            return new ByteArrayInputStream(baos.toByteArray());
        }
    }

    private static void renderText(PDPageContentStream cs, PDFont font, float fontSize, float leading,
                                   float startX, float pad, float boxHeight, List<String> lines) throws Exception {
        if (lines == null || lines.isEmpty()) return;

        float startY = boxHeight - pad - fontSize;

        cs.beginText();
        cs.setFont(font, fontSize);
        cs.setLeading(leading);
        cs.newLineAtOffset(startX, startY);

        for (int i = 0; i < lines.size(); i++) {
            String line = sanitizeText(lines.get(i));
            cs.showText(line);
            if (i < lines.size() - 1) {
                cs.newLine();
            }
        }
        cs.endText();
    }

    private static String sanitizeText(String line) {
        if (line == null) return "";
        // Clean characters unsupported by standard HELVETICA
        StringBuilder sb = new StringBuilder();
        for (char c : line.toCharArray()) {
            if (c >= 32 && c <= 255) {
                sb.append(c);
            } else {
                sb.append(' ');
            }
        }
        return sb.toString();
    }

    private static byte[] resolveImageBytes(SignatureAppearance appearance) {
        if (appearance.imageData() != null && appearance.imageData().length > 0) {
            return appearance.imageData();
        }
        if (appearance.imagePath() != null && !appearance.imagePath().isBlank()) {
            try {
                Path path = Path.of(appearance.imagePath());
                if (Files.exists(path)) {
                    return Files.readAllBytes(path);
                }
            } catch (Exception e) {
                LOG.warning("Failed to load appearance image from path: " + appearance.imagePath() + " (" + e.getMessage() + ")");
            }
        }
        return null;
    }
}
