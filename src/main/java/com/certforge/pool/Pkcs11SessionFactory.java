package com.certforge.pool;

import com.certforge.discovery.TokenInfo;

@FunctionalInterface
public interface Pkcs11SessionFactory {
    PooledSession create(TokenInfo token, String pin) throws Exception;
}
