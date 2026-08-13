package com.certforge.discovery;

public class TokenInfo {
    private final String id;
    private final String label;
    private final String manufacturer;
    private final String serial;
    private final String libraryPath;
    private final long slotId;

    public TokenInfo(String id, String label, String manufacturer, String serial,
                     String libraryPath, long slotId) {
        this.id = id;
        this.label = label;
        this.manufacturer = manufacturer;
        this.serial = serial;
        this.libraryPath = libraryPath;
        this.slotId = slotId;
    }

    public String getId() { return id; }
    public String getLabel() { return label; }
    public String getManufacturer() { return manufacturer; }
    public String getSerial() { return serial; }
    public String getLibraryPath() { return libraryPath; }
    public long getSlotId() { return slotId; }
}
