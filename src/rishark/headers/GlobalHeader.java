package rishark.headers;

import utils.Utils;

public class GlobalHeader {           // 24 bytes
    private final long magicNumber;    // 4 bytes 0-3
    private final int versionMajor;   // 2 bytes 4-5
    private final int VersionMinor;   // 2 bytes 6-7
    private final long thisZone;       // 4 bytes 8-11
    private final long sigFigs;        // 4 bytes 12-15
    private final long snapLen;        // 4 bytes 16-19
    private final long network;        // 4 bytes 20-23

    public GlobalHeader(String raw, boolean isBigEndian) {
        this.magicNumber = Utils.read4bytesFromIndex(raw, 0, isBigEndian);
        this.versionMajor = Utils.read2bytesFromIndex(raw, 4, isBigEndian);
        this.VersionMinor = Utils.read2bytesFromIndex(raw, 6, isBigEndian);
        this.thisZone = Utils.read4bytesFromIndex(raw, 8, isBigEndian);
        this.sigFigs = Utils.read4bytesFromIndex(raw, 12, isBigEndian);
        this.snapLen = Utils.read4bytesFromIndex(raw, 16, isBigEndian);
        this.network = Utils.read4bytesFromIndex(raw, 20, isBigEndian);
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
}
