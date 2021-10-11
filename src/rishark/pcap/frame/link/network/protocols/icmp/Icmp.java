package rishark.pcap.frame.link.network.protocols.icmp;

import rishark.pcap.frame.link.network.IpProtocol;
import rishark.pcap.frame.link.network.protocols.NetworkProtocol;
import utils.Utils;

// TODO: Parse ICMP + verify if padding for PcapParser with continue
public class Icmp implements NetworkProtocol {

    private final int type;             // 1 byte
    private final int code;             // 1 byte
    private final int checksum;         // 2 bytes
    private final int identifier;       // 2 bytes
    private final int sequenceNumber;   // 2 bytes
    private final long timeStamp;       // 4 bytes
    private final long padding;         // 4 bytes
    private final String data;          // 48 bytes

    private final String raw;

    public Icmp (String raw) {
        this.type = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 0, 1));
        this.code = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 1, 1));
        this.checksum = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 2, 2));
        this.identifier = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 4, 2));
        this.sequenceNumber = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 6, 2));
        this.timeStamp = Utils.hexStringToLong(Utils.readBytesFromIndex(raw, 8, 4, false));
        this.padding = Utils.hexStringToLong(Utils.readBytesFromIndex(raw, 12, 4));
        this.data = Utils.readBytesFromIndex(raw, 16, 44); // TODO BUG normalement 48
        this.raw = raw; // TODO: edit value (test)
    }

    @Override // TODO: edit value
    public int getIpProtocol() {
        return IpProtocol.ICMP.getProtocol();
    }

    public String getRaw() {
        return raw;
    }

    public int getType() {
        return type;
    }

    public int getCode() {
        return code;
    }

    public int getChecksum() {
        return checksum;
    }

    public int getIdentifier() {
        return identifier;
    }

    public int getSequenceNumber() {
        return sequenceNumber;
    }

    public long getTimeStamp() {
        return timeStamp;
    }

    public String getData() {
        return data;
    }
}
