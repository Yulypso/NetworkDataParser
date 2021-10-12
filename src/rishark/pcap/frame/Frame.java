package rishark.pcap.frame;

import rishark.pcap.frame.link.LinkFrame;
import utils.Utils;

public class Frame {
    private final PacketHeader packetHeader;
    private final LinkFrame linkFrame;
    private final String raw; //retrieve size + position start: Blob without any specific byte order

    private final int lastPos;

    public Frame(String raw, int pos, boolean isBigEndian) {
        this.packetHeader = new PacketHeader(raw, pos, isBigEndian);
        final int packetDataLength = (int) this.packetHeader.getOrigLen();
        this.raw = Utils.readBytesFromIndex(raw, this.packetHeader.getLastPos(), packetDataLength);
        this.lastPos = this.getPacketHeader().getLastPos() + packetDataLength;
        this.linkFrame = new LinkFrame(this.raw);
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

    public LinkFrame getLinkFrame() {
        return linkFrame;
    }
}
