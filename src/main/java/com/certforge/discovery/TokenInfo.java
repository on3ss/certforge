package com.certforge.discovery;

public record TokenInfo(String id, String label, String manufacturer, String serial, String libraryPath, long slotId) {
}
