package com.certforge.discovery;

import com.sun.jna.Native;
import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
import java.util.logging.Logger;

/**
 * Probes a single PKCS#11 library file.
 * Handles library loading, initialisation, token enumeration, and cleanup.
 * Each probe is independent and thread‑safe.
 */
public class Pkcs11Probe {

    private static final Logger LOG = Logger.getLogger(Pkcs11Probe.class.getName());

    /**
     * Probes the given PKCS#11 library path with a timeout.
     *
     * @param libPath        path to the shared library (DLL/SO/DYLIB)
     * @param timeoutSeconds maximum time the probe may run
     * @return list of tokens found on that library
     * @throws Exception if the library cannot be loaded, initialised, or timed out
     */
    public static List<TokenInfo> probe(String libPath, long timeoutSeconds) throws Exception {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        Future<List<TokenInfo>> future = executor.submit(() -> doProbe(libPath));
        try {
            return future.get(timeoutSeconds, TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            LOG.fine("Probe timed out for " + libPath);
            future.cancel(true);
            throw new Exception("Probe timed out for " + libPath);
        } catch (Exception e) {
            LOG.fine("Probe failed for " + libPath + ": " + e.getMessage());
            throw e;
        } finally {
            executor.shutdownNow();
        }
    }

    private static List<TokenInfo> doProbe(String libPath) throws Exception {
        LOG.fine("Trying library: " + libPath);
        List<TokenInfo> result = new ArrayList<>();

        // Load the native library via JNA
        Pkcs11Library lib;
        try {
            lib = Native.load(libPath, Pkcs11Library.class);
        } catch (UnsatisfiedLinkError e) {
            LOG.fine("Failed to load library: " + e.getMessage());
            throw new Exception("Cannot load library", e);
        }

        // Initialise the library
        Pkcs11Library.CK_C_INITIALIZE_ARGS args = new Pkcs11Library.CK_C_INITIALIZE_ARGS();
        args.flags = Pkcs11Library.CKF_OS_LOCKING_OK;
        Pkcs11Library.CK_RV rv = lib.C_Initialize(args);
        if (rv.longValue() != Pkcs11Library.CKR_OK) {
            LOG.fine("C_Initialize failed: 0x" + Long.toHexString(rv.longValue()));
            throw new Exception("C_Initialize failed: 0x" + Long.toHexString(rv.longValue()));
        }
        LOG.fine("C_Initialize OK");

        try {
            // Count slots that have a token present
            NativeLongByReference countRef = new NativeLongByReference();
            rv = lib.C_GetSlotList((byte) 1, null, countRef);
            if (rv.longValue() != Pkcs11Library.CKR_OK) {
                LOG.fine("C_GetSlotList count failed");
                return result;
            }

            long slotCount = countRef.getValue().longValue();
            LOG.fine("Slots with token present: " + slotCount);
            if (slotCount == 0) {
                return result;
            }

            // Retrieve slot IDs
            NativeLong[] slots = new NativeLong[(int) slotCount];
            rv = lib.C_GetSlotList((byte) 1, slots, countRef);
            if (rv.longValue() != Pkcs11Library.CKR_OK) {
                LOG.fine("C_GetSlotList (slots) failed");
                return result;
            }

            // For each slot, extract token information
            for (NativeLong slot : slots) {
                long slotId = slot.longValue();  // correctly unsigned 32-bit

                Pkcs11Library.CK_TOKEN_INFO info = new Pkcs11Library.CK_TOKEN_INFO();
                rv = lib.C_GetTokenInfo(slotId, info);
                if (rv.longValue() != Pkcs11Library.CKR_OK) {
                    LOG.fine("Slot " + slotId + " token info error: 0x" + Long.toHexString(rv.longValue()));
                    continue;
                }
                info.read();

                String label = info.getLabel();
                String manufacturer = info.getManufacturer();
                String serial = info.getSerial();

                LOG.fine("Found token: " + label + " (slot " + slotId + ")");

                result.add(new TokenInfo(
                        "slot-" + slotId,
                        label,
                        manufacturer,
                        serial,
                        libPath,
                        slotId
                ));
            }
        } finally {
            // Always finalise the library
            try {
                lib.C_Finalize();
                LOG.fine("C_Finalize OK");
            } catch (Exception ignored) {
                // finalization error is not critical
            }
        }
        return result;
    }
}