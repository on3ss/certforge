package com.certforge.audit;

public enum AuditEventType {
    // Lifecycle
    GATEWAY_STARTED,
    GATEWAY_STOPPED,

    // Config
    CONFIG_LOADED,
    CONFIG_NOT_FOUND,
    CONFIG_PARSE_ERROR,

    // Discovery
    TOKEN_DISCOVERY_STARTED,
    TOKEN_DISCOVERY_COMPLETED,
    LIBRARY_PROBED,
    TOKEN_FOUND,

    // Auth
    AUTH_SUCCESS,
    AUTH_FAILED,

    // Session
    SESSION_OPENED,
    SESSION_CLOSED,
    SESSION_EXPIRED,
    SESSION_NOT_FOUND,

    // Signing
    DOCUMENT_SIGNED,
    SIGNING_FAILED,

    // Verification
    DOCUMENT_VERIFIED,
    VERIFICATION_FAILED,

    // Errors
    ERROR,

    // API
    REQUEST_RECEIVED,
    REQUEST_COMPLETED
}