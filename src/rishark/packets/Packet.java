package rishark.packets;

import rishark.packets.header.PacketHeader;
import utils.Utils;

public class Packet {
    private final PacketHeader packetHeader;
    private final String packetData; //retrieve size + position start
    private final int lastPos;

    public Packet(String raw, int pos, boolean isBigEndian) {
        this.packetHeader = new PacketHeader(raw, pos, isBigEndian);
        final int packetDataLength = (int) this.packetHeader.getOrigLen();
        this.packetData = Utils.readBytesFromIndex(raw, this.packetHeader.getLastPos(), packetDataLength, isBigEndian);
        this.lastPos = this.getPacketHeader().getLastPos() + packetDataLength;

        System.out.println("\nPacketHeader:");
        System.out.println(Utils.toHexString(this.packetHeader.getTsSec()));
        System.out.println(Utils.toHexString(this.packetHeader.getTsUsec()));
        System.out.println(Utils.toHexString(this.packetHeader.getInclLen()));
        System.out.println(Utils.toHexString(this.packetHeader.getOrigLen()));

        System.out.println("\nPacketData:");
        System.out.println("Length: " + packetDataLength);
        //thanks to header, read packet data, pos: position packetHeader
        System.out.println(this.packetData);
    }

    public PacketHeader getPacketHeader() {
        return packetHeader;
    }

    public String getPacketData() {
        return packetData;
    }

    public int getLastPos() {
        return lastPos;
    }
}
