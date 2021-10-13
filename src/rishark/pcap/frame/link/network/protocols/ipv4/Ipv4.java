package rishark.pcap.frame.link.network.protocols.ipv4;

import rishark.pcap.frame.link.network.protocols.NetworkProtocol;
import utils.Utils;

public class Ipv4 implements NetworkProtocol {
                                        // 20 bytes
    private final int version;          // 0.5 byte
    private final int headerLength;     // 0.5 byte
    private final String typeOfService; // 1 byte
    private final int totalLength;      // 2 bytes
    private final String identification;   // 2 bytes
    private final String flag;             // 1 byte
    private final int fragmentOffset;   // 1 bytes
    private final int ttl;              // 1 byte
    private final int protocol;         // 1 byte
    private final String checksum;      // 2 bytes
    private final String srcAddress;    // 4 bytes
    private final String destAddress;   // 4 bytes
    private final String options;       // variable length

    private final String raw;

    public Ipv4 (String raw) {
        this.version = Utils.hexStringToInt(String.valueOf(Utils.readBytesFromIndex(raw, 0, 1).charAt(0)));
        this.headerLength = Utils.hexStringToInt(String.valueOf(Utils.readBytesFromIndex(raw, 0, 1).charAt(1))) * 4;
        this.typeOfService = Utils.hexStringToBinary(Utils.readBytesFromIndex(raw, 1, 1));
        this.totalLength = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 2, 2));
        this.identification = Utils.readBytesFromIndex(raw, 4, 2);
        this.flag = Utils.hexStringToBinary(Utils.readBytesFromIndex(raw, 6, 1));
        this.fragmentOffset = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 7, 1));
        this.ttl = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 8, 1));
        this.protocol = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 9, 1));
        this.checksum = Utils.readBytesFromIndex(raw, 10, 2);
        this.srcAddress = Utils.readBytesFromIndex(raw, 12, 4);
        this.destAddress = Utils.readBytesFromIndex(raw, 16, 4);
        this.options = Utils.readBytesFromIndex(raw, 20, this.headerLength - 20);
        this.raw = Utils.readBytesFromIndex(raw, this.headerLength, (raw.length()/2) - this.headerLength);
    }

    public int getVersion() {
        return version;
    }

    public int getHeaderLength() {
        return headerLength;
    }

    public String getTypeOfService() {
        return typeOfService;
    }

    public long getTotalLength() {
        return totalLength;
    }

    public String getIdentification() {
        return identification;
    }

    public String getFlag() {
        return flag;
    }

    public int getFragmentOffset() {
        return fragmentOffset;
    }

    public int getTtl() {
        return ttl;
    }

    public int getIpProtocol() {
        return protocol;
    }

    public String getChecksum() {
        return checksum;
    }

    public String getSrcAddress() {
        return srcAddress;
    }

    public String getDestAddress() {
        return destAddress;
    }

    public String getRaw() {
        return raw;
    }

    public long getSize() {
        return this.getHeaderLength();
    }

    public String getOptions() {
        return options;
    }
}
