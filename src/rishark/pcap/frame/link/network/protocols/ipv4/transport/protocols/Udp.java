package rishark.pcap.frame.link.network.protocols.ipv4.transport.protocols;

import utils.Utils;

public class Udp implements TransportProtocol {
                                        // 8 bytes
    private final int sourcePort;       // 2 bytes
    private final int destPort;         // 2 bytes
    private final int length;           // 2 bytes
    private final String checksum;      // 2 bytes
    private final String raw;

    public Udp(String raw) {
        this.sourcePort = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 0, 2));
        this.destPort = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 2, 2));
        this.length = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 4, 2));
        this.checksum = Utils.readBytesFromIndex(raw, 6, 2);
        this.raw = Utils.readBytesFromIndex(raw, 8, (raw.length()/2) - 8);
    }

    @Override
    public String getRaw() {
        return raw;
    }

    public int getSourcePort() {
        return sourcePort;
    }

    public int getDestPort() {
        return destPort;
    }

    public long getLength() {
        return length;
    }

    public String getChecksum() {
        return checksum;
    }
}
