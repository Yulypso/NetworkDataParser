package rishark.pcap.physicalbit.header;

import utils.Utils;

public class PhysicalBitHeader {         // 16 bytes
    private final long tsSec;       // timestamp in secondes 4 bytes 0-3
    private final long tsUsec;      // timestamp in microseconds 4 bytes 4-7
    private final long inclLen;     // number of octets of packet saved in file 4 bytes 8-11
    private final long origLen;     // actual length of packet 4 bytes 12-15

    private final int lastPos;

    public PhysicalBitHeader(String raw, int pos, boolean isBigEndian){
        this.tsSec = Utils.hexStringToLong(Utils.readBytesFromIndex(raw, pos, 4, isBigEndian));
        this.tsUsec = Utils.hexStringToLong(Utils.readBytesFromIndex(raw, pos+4, 4, isBigEndian));
        this.inclLen = Utils.hexStringToLong(Utils.readBytesFromIndex(raw, pos+8, 4, isBigEndian));
        this.origLen = Utils.hexStringToLong(Utils.readBytesFromIndex(raw, pos+12, 4, isBigEndian));

        int length = 16;
        this.lastPos = pos + length;
    }

    public long getTsSec() {
        return tsSec;
    }

    public long getTsUsec() {
        return tsUsec;
    }

    public long getInclLen() {
        return inclLen;
    }

    public long getOrigLen() {
        return origLen;
    }

    public int getLastPos() {
        return lastPos;
    }
}
