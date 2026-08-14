package com.certforge.discovery;

import com.sun.jna.*;
import com.sun.jna.ptr.LongByReference;
import com.sun.jna.ptr.NativeLongByReference;

import java.util.Arrays;
import java.util.List;

public interface Pkcs11Library extends Library {

    long CKF_OS_LOCKING_OK = 0x00000002L;
    long CKR_OK = 0x00000000L;

    CK_RV C_Initialize(CK_C_INITIALIZE_ARGS args);

    CK_RV C_GetSlotList(byte tokenPresent, NativeLong[] slotList, NativeLongByReference count);

    CK_RV C_GetTokenInfo(long slotID, CK_TOKEN_INFO tokenInfo);

    CK_RV C_Finalize();

    class CK_C_INITIALIZE_ARGS extends Structure {
        public Pointer CreateMutex;
        public Pointer DestroyMutex;
        public Pointer LockMutex;
        public Pointer UnlockMutex;
        public long flags;
        public Pointer pReserved;

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("CreateMutex", "DestroyMutex", "LockMutex",
                    "UnlockMutex", "flags", "pReserved");
        }
    }

    class CK_RV extends NativeLong {
        public CK_RV() {
            super(0);
        }

        public CK_RV(long value) {
            super(value);
        }
    }

    class CK_VERSION extends Structure {
        public byte major;
        public byte minor;

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("major", "minor");
        }
    }

    class CK_TOKEN_INFO extends Structure {
        public byte[] label = new byte[32];
        public byte[] manufacturerID = new byte[32];
        public byte[] model = new byte[16];
        public byte[] serialNumber = new byte[16];
        public long flags;
        public long ulMaxSessionCount;
        public long ulSessionCount;
        public long ulMaxRwSessionCount;
        public long ulRwSessionCount;
        public long ulMaxPinLen;
        public long ulMinPinLen;
        public long ulTotalPublicMemory;
        public long ulFreePublicMemory;
        public long ulTotalPrivateMemory;
        public long ulFreePrivateMemory;
        public CK_VERSION hardwareVersion;
        public CK_VERSION firmwareVersion;

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList(
                    "label", "manufacturerID", "model", "serialNumber",
                    "flags",
                    "ulMaxSessionCount", "ulSessionCount",
                    "ulMaxRwSessionCount", "ulRwSessionCount",
                    "ulMaxPinLen", "ulMinPinLen",
                    "ulTotalPublicMemory", "ulFreePublicMemory",
                    "ulTotalPrivateMemory", "ulFreePrivateMemory",
                    "hardwareVersion", "firmwareVersion"
            );
        }

        public String getLabel() {
            return new String(label).trim();
        }

        public String getManufacturer() {
            return new String(manufacturerID).trim();
        }

        public String getSerial() {
            return new String(serialNumber).trim();
        }
    }
}