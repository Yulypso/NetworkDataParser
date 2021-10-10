package rishark.pcap.frame.link.protocols.arp;

import rishark.pcap.frame.link.protocols.LinkProtocol;
import utils.Utils;

public class Arp implements LinkProtocol {
                                            // 28 bytes
    private final int hardwareType;         // 2 bytes
    private final String protocolType;      // 2 bytes
    private final int hardwareSize;         // 1 byte
    private final int protocolSize;         // 1 byte
    private final int opCode;               // 2 bytes
    private final String senderMacAddress;  // 6 bytes
    private final String senderIpAddress;   // 4 bytes
    private final String targetMacAddress;  // 6 bytes
    private final String targetIpAddress;   // 4 bytes

    private final String padding;

    public Arp(String raw) {
        this.hardwareType = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 0, 2));
        this.protocolType = Utils.readBytesFromIndex(raw, 2, 2);
        this.hardwareSize = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 4, 1));
        this.protocolSize = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 5, 1));
        this.opCode = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 6, 2));
        this.senderMacAddress = Utils.readBytesFromIndex(raw, 8, 6);
        this.senderIpAddress = Utils.readBytesFromIndex(raw, 14, 4);
        this.targetMacAddress = Utils.readBytesFromIndex(raw, 18, 6);
        this.targetIpAddress = Utils.readBytesFromIndex(raw, 24, 4);

        this.padding = Utils.readBytesFromIndex(raw, (int) this.getSize(), (int) ((raw.length() / 2) - this.getSize()));
    }

    public int getHardwareType() {
        return hardwareType;
    }

    public String getProtocolType() {
        return protocolType;
    }

    public int getHardwareSize() {
        return hardwareSize;
    }

    public int getProtocolSize() {
        return protocolSize;
    }

    public int getOpCode() {
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

    public String getPadding() {
        return (this.padding != null ? Utils.readBytesFromIndex(padding, 0, this.padding.length() / 2) : null);
    }

    @Override
    public long getSize() {
        return (getPadding() == null ? 28 : 28 + getPadding().length() / 2);
    }
}
