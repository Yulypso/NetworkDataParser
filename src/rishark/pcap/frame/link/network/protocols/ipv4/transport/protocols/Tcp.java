package rishark.pcap.frame.link.network.protocols.ipv4.transport.protocols;

import utils.Utils;

// TCP flow: use sourcePort and destPort to get the first sequenceNumber + use sequenceNumber and AckNumber
// TODO: TCP OPTIONS with header

public class Tcp implements TransportProtocol{
                                                // 20 bytes
    private final int sourcePort;               // 2 bytes
    private final int destPort;                 // 2 bytes
    private final long sequenceNumber;          // 4 bytes
    private final long acknowledgmentNumber;    // 4 bytes
    private final int headerLength;             // 0.5 byte (TCP Header length, show where data starts)
    private final String reserved;              // 1 byte + 2 bits (6 bits)
    private final String flags;                 // 2 bits + 1 byte (6 bits)
    private final int window;                   // 2 bytes
    private final String checksum;              // 2 bytes
    private final int urgentPointer;            // 2 bytes
    private final String options;               // variable length

    private final String raw;

    public Tcp(String raw) {
        this.sourcePort = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 0, 2));
        this.destPort = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 2, 2));
        this.sequenceNumber = Utils.hexStringToLong(Utils.readBytesFromIndex(raw, 4, 4));
        this.acknowledgmentNumber = Utils.hexStringToLong(Utils.readBytesFromIndex(raw, 8, 4));
        this.headerLength = Utils.binaryStringToInt(Utils.hexStringToBinary(Utils.readBytesFromIndex(raw, 12, 2)).substring(0, 4)) * 4;
        this.reserved = Utils.hexStringToBinary(Utils.readBytesFromIndex(raw, 12, 2)).substring(4, 10);
        this.flags = Utils.hexStringToBinary(Utils.readBytesFromIndex(raw, 12, 2)).substring(10, 16);
        this.window = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 14, 2));
        this.checksum = Utils.readBytesFromIndex(raw, 16, 2);
        this.urgentPointer = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 18, 2));
        this.options = Utils.readBytesFromIndex(raw, 20, this.headerLength - 20);
        this.raw = Utils.readBytesFromIndex(raw, this.headerLength, (raw.length()/2) - this.headerLength);
    }

    @Override
    public String getRaw() {
        return this.raw;
    }

    public int getSourcePort() {
        return sourcePort;
    }

    public int getDestPort() {
        return destPort;
    }

    public long getSequenceNumber() {
        return sequenceNumber;
    }

    public long getAcknowledgmentNumber() {
        return acknowledgmentNumber;
    }

    public int getHeaderLength() {
        return headerLength;
    }

    public String getReserved() {
        return reserved;
    }

    public String getFlags() {
        return flags;
    }

    public int getWindow() {
        return window;
    }

    public String getChecksum() {
        return checksum;
    }

    public int getUrgentPointer() {
        return urgentPointer;
    }

    public String getOptions() {
        return options;
    }
}
