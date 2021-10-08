package rishark.pcap.physicalbit;

import rishark.pcap.physicalbit.header.PhysicalBitHeader;
import utils.Utils;

public class PhysicalBit {
    private final PhysicalBitHeader physicalBitHeader;
    private final String physicalBitData; //retrieve size + position start: Blob without any specific byte order
    private final int lastPos;

    public PhysicalBit(String raw, int pos, boolean isBigEndian) {
        this.physicalBitHeader = new PhysicalBitHeader(raw, pos, isBigEndian);
        final int packetDataLength = (int) this.physicalBitHeader.getOrigLen();
        this.physicalBitData = Utils.readBytesFromIndex(raw, this.physicalBitHeader.getLastPos(), packetDataLength);
        this.lastPos = this.getPhysicalBitHeader().getLastPos() + packetDataLength;

        System.out.println("\nPacketHeader:");
        System.out.println(Utils.toHexString(this.physicalBitHeader.getTsSec()));
        System.out.println(Utils.toHexString(this.physicalBitHeader.getTsUsec()));
        System.out.println(Utils.toHexString(this.physicalBitHeader.getInclLen()));
        System.out.println(Utils.toHexString(this.physicalBitHeader.getOrigLen()));

        System.out.println("\nPacketData:");
        System.out.println("Length: " + packetDataLength);
        //thanks to header, read packet data, pos: position packetHeader
        System.out.println(this.physicalBitData);
    }

    public PhysicalBitHeader getPhysicalBitHeader() {
        return physicalBitHeader;
    }

    public String getPhysicalBitData() {
        return physicalBitData;
    }

    public int getLastPos() {
        return lastPos;
    }
}
