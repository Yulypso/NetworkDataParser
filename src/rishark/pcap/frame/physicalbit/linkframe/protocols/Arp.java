package rishark.pcap.frame.physicalbit.linkframe.protocols;

import utils.Utils;

public class Arp implements LinkProtocol {
                                            // 28 bytes
    private final String hardwareType;      // 2 bytes
    private final String protocolType;      // 2 bytes
    private final String hardwareSize;      // 1 byte
    private final String protocolSize;      // 1 byte
    private final String opCode;            // 2 bytes
    private final String senderMacAddress;  // 6 bytes
    private final String senderIpAddress;   // 4 bytes
    private final String targetMacAddress;  // 6 bytes
    private final String targetIpAddress;   // 4 bytes

    public Arp(String raw) {
        this.hardwareType = Utils.readBytesFromIndex(raw, 0, 2);
        this.protocolType = Utils.readBytesFromIndex(raw, 2, 2);
        this.hardwareSize = Utils.readBytesFromIndex(raw, 4, 1);
        this.protocolSize = Utils.readBytesFromIndex(raw, 5, 1);
        this.opCode = Utils.readBytesFromIndex(raw, 6, 2);
        this.senderMacAddress = Utils.readBytesFromIndex(raw, 8, 6);
        this.senderIpAddress = Utils.readBytesFromIndex(raw, 14, 4);
        this.targetMacAddress = Utils.readBytesFromIndex(raw, 18, 6);
        this.targetIpAddress = Utils.readBytesFromIndex(raw, 24, 4);
    }

    public String getHardwareType() {
        return hardwareType;
    }

    public String getProtocolType() {
        return protocolType;
    }

    public String getHardwareSize() {
        return hardwareSize;
    }

    public String getProtocolSize() {
        return protocolSize;
    }

    public String getOpCode() {
        return opCode;
    }

    public String getSenderMacAddress() {
        return senderMacAddress;
    }

    public String getSenderIpAddress() {
        return senderIpAddress;
    }

    public String getTargetMacAddress() {
        return targetMacAddress;
    }

    public String getTargetIpAddress() {
        return targetIpAddress;
    }
}
