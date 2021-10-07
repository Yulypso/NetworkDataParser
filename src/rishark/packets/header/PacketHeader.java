package rishark.packets.header;

import utils.Utils;

public class PacketHeader {         // 16 bytes
    private final long tsSec;       // 4 bytes 0-3
    private final long tsUsec;      // 4 bytes 4-7
    private final long inclLen;     // 4 bytes 8-11
    private final long origLen;     // 4 bytes 12-15

    private final int lastPos;

    public PacketHeader(String raw, int pos, boolean isBigEndian){
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
