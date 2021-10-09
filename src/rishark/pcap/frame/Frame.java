package rishark.pcap.frame;

import rishark.pcap.frame.physicalbit.PhysicalBit;
import utils.Utils;

public class Frame {
    private final PacketHeader packetHeader;
    private final PhysicalBit physicalBit;
    private final String raw; //retrieve size + position start: Blob without any specific byte order

    private final int lastPos;

    public Frame(String raw, int pos, boolean isBigEndian) {
        this.packetHeader = new PacketHeader(raw, pos, isBigEndian);
        final int packetDataLength = (int) this.packetHeader.getOrigLen();
        this.raw = Utils.readBytesFromIndex(raw, this.packetHeader.getLastPos(), packetDataLength);
        this.lastPos = this.getPacketHeader().getLastPos() + packetDataLength;

        System.out.println("\nPacketHeader:");
        System.out.println(Utils.toHexString(this.packetHeader.getTsSec()));
        System.out.println(Utils.toHexString(this.packetHeader.getTsUsec()));
        System.out.println(Utils.toHexString(this.packetHeader.getInclLen()));
        System.out.println(Utils.toHexString(this.packetHeader.getOrigLen()));

        System.out.println("\nPacketData:");
        System.out.println("Length: " + packetDataLength);
        //thanks to header, read packet data, pos: position packetHeader
        //System.out.println(this.raw);

        this.physicalBit = new PhysicalBit(this.raw);
    }

    public PacketHeader getPacketHeader() {
        return packetHeader;
    }

    public String getRaw() {
        return raw;
    }

    public int getLastPos() {
        return lastPos;
    }

    public PhysicalBit getPhysicalBit() {
        return physicalBit;
    }
}
