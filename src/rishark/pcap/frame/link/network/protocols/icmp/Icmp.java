package rishark.pcap.frame.link.network.protocols.icmp;

import rishark.pcap.frame.link.network.IpProtocol;
import rishark.pcap.frame.link.network.protocols.NetworkProtocol;
import utils.Utils;

// TODO: Parse ICMP + verify if padding for PcapParser with continue
public class Icmp implements NetworkProtocol {

    private final int type;             // 1 byte
    private final int code;             // 1 byte
    private final String checksum;         // 2 bytes
    private final String identifierBE;       // 2 bytes
    private final String identifierLE;       // 2 bytes
    private final String sequenceNumberBE;   // 2 bytes
    private final String sequenceNumberLE;   // 2 bytes
    private final long timeStamp;       // 4 bytes
    private final long padding;         // 4 bytes
    private final String data;          // 48 bytes

    private final String raw;

    public Icmp (String raw) {
        this.type = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 0, 1));
        this.code = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 1, 1));
        this.checksum = Utils.readBytesFromIndex(raw, 2, 2);
        this.identifierBE = Utils.readBytesFromIndex(raw, 4, 2, true);
        this.identifierLE = Utils.readBytesFromIndex(raw, 4, 2, false);
        this.sequenceNumberBE = Utils.readBytesFromIndex(raw, 6, 2, true);
        this.sequenceNumberLE = Utils.readBytesFromIndex(raw, 6, 2, false);
        this.timeStamp = Utils.hexStringToLong(Utils.readBytesFromIndex(raw, 8, 4, false));
        this.padding = Utils.hexStringToLong(Utils.readBytesFromIndex(raw, 12, 4));
        this.data = Utils.readBytesFromIndex(raw, 16, 48); // TODO BUG normalement 48
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

    public String getChecksum() {
        return checksum;
    }

    public String getIdentifierBE() {
        return identifierBE;
    }

    public String getIdentifierLE() {
        return identifierLE;
    }

    public String getSequenceNumberBE() {
        return sequenceNumberBE;
    }

    public String getSequenceNumberLE() {
        return sequenceNumberLE;
    }

    public long getTimeStamp() {
        return timeStamp;
    }

    public String getData() {
        return data;
    }
}
