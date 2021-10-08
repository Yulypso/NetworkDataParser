package rishark.pcap.frames;

import rishark.pcap.frames.physicalbit.PhysicalBit;
import utils.Utils;

public class Frame {
    private final PacketHeader packetHeader;
    private final String frameData; //retrieve size + position start: Blob without any specific byte order
    private final int lastPos;

    public Frame(String raw, int pos, boolean isBigEndian) {
        this.packetHeader = new PacketHeader(raw, pos, isBigEndian);
        final int packetDataLength = (int) this.packetHeader.getOrigLen();
        this.frameData = Utils.readBytesFromIndex(raw, this.packetHeader.getLastPos(), packetDataLength);
        this.lastPos = this.getPacketHeader().getLastPos() + packetDataLength;

        System.out.println("\nPacketHeader:");
        System.out.println(Utils.toHexString(this.packetHeader.getTsSec()));
        System.out.println(Utils.toHexString(this.packetHeader.getTsUsec()));
        System.out.println(Utils.toHexString(this.packetHeader.getInclLen()));
        System.out.println(Utils.toHexString(this.packetHeader.getOrigLen()));

        System.out.println("\nPacketData:");
        System.out.println("Length: " + packetDataLength);
        //thanks to header, read packet data, pos: position packetHeader
        System.out.println(this.frameData);

        // TODO
        //PhysicalBit physicalBit = new PhysicalBit(this.frameData);
    }

    public PacketHeader getPacketHeader() {
        return packetHeader;
    }

    public String getFrameData() {
        return frameData;
    }

    public int getLastPos() {
        return lastPos;
    }
}
