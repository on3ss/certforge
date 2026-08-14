package com.certforge.pool;

public record PoolConfig(
        int maxTotal,
        int maxIdle,
        int idleTimeoutSeconds,
        int maxLifetimeSeconds,
        int validationIntervalSeconds,
        long borrowTimeoutMs
) {
    public static PoolConfig defaultConfig() {
        return new PoolConfig(10, 5, 600, 3600, 30, 2000L);
    }
}
