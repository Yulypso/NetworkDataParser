package rishark.header;

import utils.Utils;

public class GlobalHeader {            // 24 bytes
    private final long magicNumber;    // 4 bytes 0-3
    private final int versionMajor;    // 2 bytes 4-5
    private final int VersionMinor;    // 2 bytes 6-7
    private final long thisZone;       // 4 bytes 8-11
    private final long sigFigs;        // 4 bytes 12-15
    private final long snapLen;        // 4 bytes 16-19
    private final long network;        // 4 bytes 20-23

    public GlobalHeader(String raw, boolean isBigEndian) {
        this.magicNumber = Utils.hexStringToLong(Utils.readBytesFromIndex(raw, 0, 4, isBigEndian));
        this.versionMajor = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 4, 2, isBigEndian));
        this.VersionMinor = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 6, 2, isBigEndian));
        this.thisZone =  Utils.hexStringToLong(Utils.readBytesFromIndex(raw, 8, 4, isBigEndian));
        this.sigFigs = Utils.hexStringToLong(Utils.readBytesFromIndex(raw, 12, 4, isBigEndian));
        this.snapLen = Utils.hexStringToLong(Utils.readBytesFromIndex(raw, 16, 4, isBigEndian));
        this.network = Utils.hexStringToLong(Utils.readBytesFromIndex(raw, 20, 4, isBigEndian));
    }

    public long getMagicNumber() {
        return magicNumber;
    }

    public int getVersionMajor() {
        return versionMajor;
    }

    public int getVersionMinor() {
        return VersionMinor;
    }

    public long getThisZone() {
        return thisZone;
    }

    public long getSigFigs() {
        return sigFigs;
    }

    public long getSnapLen() {
        return snapLen;
    }

    public long getNetwork() {
        return network;
    }

    public int getLength() {
        return 24;
    }
}
