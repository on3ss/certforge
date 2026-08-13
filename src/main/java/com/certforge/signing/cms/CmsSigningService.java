package com.certforge.signing.cms;

import com.certforge.audit.AuditLogger;
import com.certforge.signing.crypto.CryptoSigner;
import com.certforge.signing.exception.PdfSigningException;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CmsSigningService {

    private static final Logger LOG = Logger.getLogger(CmsSigningService.class.getName());
    private final AuditLogger auditLogger;

    public CmsSigningService(AuditLogger auditLogger) {
        this.auditLogger = auditLogger;
    }

    public byte[] createDetachedSignature(byte[] content, CryptoSigner cryptoSigner)
            throws PdfSigningException {
        try {
            LOG.fine(() -> "Creating detached CMS signature over " + content.length + " bytes");
            LOG.fine(() -> "Signature algorithm: " + cryptoSigner.getSignatureAlgorithm());
            LOG.fine(() -> "Signer certificate subject: " +
                    cryptoSigner.getCertificateChain()[0].getSubjectX500Principal().getName());

            CMSTypedData cmsData = new CMSProcessableByteArray(content);
            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

            DelegatingContentSigner delegatingSigner = new DelegatingContentSigner(
                    cryptoSigner.getSignatureAlgorithm(),
                    cryptoSigner
            );

            generator.addSignerInfoGenerator(
                    new JcaSignerInfoGeneratorBuilder(
                            new JcaDigestCalculatorProviderBuilder().build()
                    ).build(delegatingSigner, cryptoSigner.getCertificateChain()[0])
            );

            generator.addCertificates(new JcaCertStore(
                    Arrays.asList(cryptoSigner.getCertificateChain())
            ));

            CMSSignedData signedData = generator.generate(cmsData, false);
            byte[] encoded = signedData.getEncoded();

            LOG.fine(() -> "CMS signature created successfully: " + encoded.length + " bytes");
            return encoded;

        } catch (Exception e) {
            LOG.log(Level.SEVERE, "Failed to create CMS signature: " + e.getMessage(), e);

            // Audit: CMS construction failed
            auditLogger.logError("cms_signature_creation",
                    "Failed to create CMS signature: " + e.getMessage());

            throw new PdfSigningException("Failed to create CMS signature", e);
        }
    }
}