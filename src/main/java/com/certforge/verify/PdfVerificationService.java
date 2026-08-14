package com.certforge.verify;

import com.certforge.audit.AuditLogger;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.CollectionStore;

import java.io.ByteArrayInputStream;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

public class PdfVerificationService implements VerificationService {

    private static final Logger LOG = Logger.getLogger(PdfVerificationService.class.getName());
    private final AuditLogger auditLogger;

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
            LOG.info("BouncyCastle provider registered");
        }
    }

    public PdfVerificationService(AuditLogger auditLogger) {
        this.auditLogger = Objects.requireNonNull(auditLogger, "auditLogger cannot be null");
    }

    @Override
    public VerificationResult verify(byte[] pdfBytes) {
        List<VerificationResult.SignatureVerification> signatures = new ArrayList<>();
        boolean overallValid = true;

        try (PDDocument document = Loader.loadPDF(pdfBytes)) {
            List<PDSignature> signatureDictionaries = document.getSignatureDictionaries();
            LOG.info("Found " + signatureDictionaries.size() + " signature(s) in PDF");

            if (signatureDictionaries.isEmpty()) {
                auditLogger.logVerifyEvent("no_signatures", 0);
                return new VerificationResult(false, List.of());
            }

            for (PDSignature signature : signatureDictionaries) {
                VerificationResult.SignatureVerification result = verifySignature(pdfBytes, signature);
                signatures.add(result);
                if (!result.certificateValid() || !"intact".equals(result.integrity())) {
                    overallValid = false;
                }
            }

            auditLogger.logVerifyEvent(overallValid ? "valid" : "invalid", signatures.size());
            return new VerificationResult(overallValid, signatures);

        } catch (Exception e) {
            LOG.log(Level.SEVERE, "PDF verification failed: " + e.getMessage(), e);
            auditLogger.logVerificationFailed(e.getMessage());
            return new VerificationResult(false, List.of());
        }
    }

    private VerificationResult.SignatureVerification verifySignature(byte[] pdfBytes, PDSignature signature) {
        try {
            byte[] signatureContent = signature.getContents();
            byte[] signedContent = extractSignedContent(pdfBytes, signature);

            if (signatureContent == null || signedContent == null) {
                return new VerificationResult.SignatureVerification(
                        "Unknown", "Unknown", "corrupted", false, "Unknown"
                );
            }

            CMSSignedData cmsData = new CMSSignedData(
                    new CMSProcessableByteArray(signedContent),
                    signatureContent
            );

            SignerInformationStore signerStore = cmsData.getSignerInfos();
            Collection<SignerInformation> signers = signerStore.getSigners();

            if (signers.isEmpty()) {
                return new VerificationResult.SignatureVerification(
                        "Unknown", "Unknown", "no_signer", false, "Unknown"
                );
            }

            SignerInformation signerInfo = signers.iterator().next();

            X509Certificate cert = getCertificateFromStore(cmsData, signerInfo);
            if (cert == null) {
                return new VerificationResult.SignatureVerification(
                        "Unknown", "Unknown", "certificate_not_found", false, "Unknown"
                );
            }

            String integrity;
            try {
                boolean signatureValid = signerInfo.verify(
                        new org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder()
                                .setProvider("BC")
                                .build(cert)
                );
                integrity = signatureValid ? "intact" : "broken";
            } catch (Exception e) {
                integrity = "verification_failed: " + e.getMessage();
            }

            String signer = cert.getSubjectX500Principal().getName();
            String signedAt = signature.getSignDate() != null
                    ? signature.getSignDate().toInstant().toString()
                    : "Unknown";
            String certExpiry = cert.getNotAfter().toInstant().toString();

            boolean certValid;
            try {
                cert.checkValidity();
                certValid = true;
            } catch (Exception e) {
                certValid = false;
            }

            return new VerificationResult.SignatureVerification(
                    signer, signedAt, integrity, certValid, certExpiry
            );

        } catch (Exception e) {
            LOG.fine(() -> "Failed to verify individual signature: " + e.getMessage());
            return new VerificationResult.SignatureVerification(
                    "Unknown", "Unknown", "error: " + e.getMessage(), false, "Unknown"
            );
        }
    }

    private byte[] extractSignedContent(byte[] pdfBytes, PDSignature signature) {
        try {
            int[] byteRange = signature.getByteRange();
            if (byteRange == null || byteRange.length != 4) {
                return null;
            }

            int start1 = byteRange[0];
            int length1 = byteRange[1];
            int start2 = byteRange[2];
            int length2 = byteRange[3];

            byte[] result = new byte[length1 + length2];
            System.arraycopy(pdfBytes, start1, result, 0, length1);
            System.arraycopy(pdfBytes, start2, result, length1, length2);
            return result;

        } catch (Exception e) {
            LOG.fine(() -> "Failed to extract signed content: " + e.getMessage());
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    private X509Certificate getCertificateFromStore(CMSSignedData cmsData, SignerInformation signerInfo) {
        try {
            CollectionStore<X509CertificateHolder> certStore =
                    (CollectionStore<X509CertificateHolder>) cmsData.getCertificates();
            Collection<X509CertificateHolder> certs = certStore.getMatches(signerInfo.getSID());

            if (certs.isEmpty()) return null;

            X509CertificateHolder certHolder = certs.iterator().next();
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(
                    new ByteArrayInputStream(certHolder.getEncoded())
            );
        } catch (Exception e) {
            LOG.fine(() -> "Failed to extract certificate: " + e.getMessage());
            return null;
        }
    }
}