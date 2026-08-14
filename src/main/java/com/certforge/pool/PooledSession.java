package com.certforge.pool;

import com.certforge.discovery.TokenInfo;

import java.security.KeyStore;
import java.security.Provider;
import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;

public class PooledSession {

    private final String id;
    private final TokenInfo token;
    private final Provider provider;
    private final KeyStore keyStore;
    private final char[] pin;
    private final Instant createdAt;
    private volatile Instant lastUsed;
    private volatile boolean valid = true;
    private volatile boolean closed = false;

    public PooledSession(TokenInfo token, Provider provider, KeyStore keyStore, char[] pin, Instant now) {
        this.id = UUID.randomUUID().toString().replace("-", "");
        this.token = token;
        this.provider = provider;
        this.keyStore = keyStore;
        this.pin = pin;
        this.createdAt = now;
        this.lastUsed = now;
    }

    public String id() {
        return id;
    }

    public TokenInfo token() {
        return token;
    }

    public Provider provider() {
        return provider;
    }

    public KeyStore keyStore() {
        return keyStore;
    }

    public char[] pin() {
        return pin;
    }

    public Instant createdAt() {
        return createdAt;
    }

    public Instant lastUsed() {
        return lastUsed;
    }

    public void touch(Instant now) {
        this.lastUsed = now;
    }

    public boolean isValid() {
        return valid && !closed;
    }

    public void setValid(boolean valid) {
        this.valid = valid;
    }

    public boolean isClosed() {
        return closed;
    }

    public synchronized void close() {
        if (!closed) {
            closed = true;
            valid = false;
            wipePin();
        }
    }

    private void wipePin() {
        if (pin != null) {
            Arrays.fill(pin, '0');
        }
    }
}
