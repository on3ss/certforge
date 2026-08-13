package com.certforge.verify;

import java.util.List;

/**
 * Structured verification report for a signed PDF.
 */
public record VerificationResult(boolean valid, List<SignatureVerification> signatures) {

    public VerificationResult(boolean valid, List<SignatureVerification> signatures) {
        this.valid = valid;
        this.signatures = List.copyOf(signatures);
    }

    /**
     * Individual signature verification details.
     */
    public record SignatureVerification(String signer, String signedAt, String integrity, boolean certificateValid,
                                        String certificateExpiry) {
    }

    public String toJson() {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"valid\":").append(valid).append(",\"signatures\":[");
        for (int i = 0; i < signatures.size(); i++) {
            SignatureVerification s = signatures.get(i);
            if (i > 0) sb.append(",");
            sb.append("{")
                    .append("\"signer\":\"").append(escapeJson(s.signer())).append("\",")
                    .append("\"signedAt\":\"").append(escapeJson(s.signedAt())).append("\",")
                    .append("\"integrity\":\"").append(escapeJson(s.integrity())).append("\",")
                    .append("\"certificateValid\":").append(s.certificateValid()).append(",")
                    .append("\"certificateExpiry\":\"").append(escapeJson(s.certificateExpiry())).append("\"")
                    .append("}");
        }
        sb.append("]}");
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