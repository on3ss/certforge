package com.certforge.pool;

import com.certforge.discovery.TokenInfo;

import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.time.Instant;
import java.util.logging.Logger;

public class SunPkcs11SessionFactory implements Pkcs11SessionFactory {

    private static final Logger LOG = Logger.getLogger(SunPkcs11SessionFactory.class.getName());

    @Override
    public PooledSession create(TokenInfo token, String pin) throws Exception {
        String config = "--name=CertForge-" + token.id() + "-" + System.nanoTime() + "\n" +
                "library=" + token.libraryPath() + "\n" +
                "slot=" + token.slotId() + "\n";

        Provider provider = Security.getProvider("SunPKCS11");
        if (provider != null) {
            provider = provider.configure(config);
        } else {
            provider = new sun.security.pkcs11.SunPKCS11().configure(config);
        }
        Security.addProvider(provider);

        char[] pinChars = pin != null ? pin.toCharArray() : new char[0];
        KeyStore ks;
        try {
            ks = KeyStore.getInstance("PKCS11", provider);
            ks.load(null, pinChars);
        } catch (Exception e) {
            try {
                Security.removeProvider(provider.getName());
            } catch (Exception _) {
            }
            throw e;
        }

        LOG.info("Physical PKCS#11 session initialized for token: " + token.id());
        return new PooledSession(token, provider, ks, pinChars, Instant.now());
    }
}
