package rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dhcp;

import rishark.pcap.frame.link.network.Protocol;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.ApplicationProtocol;
import utils.Utils;

import java.util.ArrayList;
import java.util.List;

public class Dhcp implements ApplicationProtocol {
                                                // 240 bytes
    private final DHCPOpCode opCode;            // 1 byte
    private final int hardwareType;             // 1 byte
    private final int addressLength;            // 1 byte
    private final int hops;                     // 1 byte
    private final long transactionId;           // 4 bytes
    private final int secondElapsed;            // 2 bytes
    private final String flagBroadcast;         // 1 bit
    private final String flagReserved;          // 1 byte 7 bits
    private final String clientIpAddress;       // 4 bytes
    private final String yourIpAddress;         // 4 bytes
    private final String serverIpAddress;       // 4 bytes nextServerAddress
    private final String gatewayIpAddress;      // 4 bytes relayAgentIPAddress
    private final String clientMacAddress;      // 6 bytes
    private final String clientHardwarePadding; // 10 bytes
    private final String serverHostName;        // 64 bytes
    private final String bootFileName;          // 128 bytes
    private final String magicCookie;           // 4 bytes

    private final List<Option> optionList;      // variable length
    private final String padding;

    private final String raw;
    private final long udpDataLength;
    private final Protocol overProtocol;

    public Dhcp(String raw, Protocol overProtocol, long udpDataLength) {
        this.optionList = new ArrayList<>();

        this.udpDataLength = udpDataLength;
        this.opCode = DHCPOpCode.findDhcpOpCode(Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 0, 1)));
        this.hardwareType = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 1, 1));
        this.addressLength = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 2, 1));
        this.hops = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 3, 1));
        this.transactionId = Utils.hexStringToLong(Utils.readBytesFromIndex(raw, 4, 4));
        this.secondElapsed = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 8, 2));
        String flag = Utils.hexStringToBinary(Utils.readBytesFromIndex(raw, 10, 2));
        this.flagBroadcast = "" + flag.charAt(0);
        this.flagReserved = "" + flag.substring(1);
        this.clientIpAddress = Utils.readBytesFromIndex(raw, 12, 4);
        this.yourIpAddress = Utils.readBytesFromIndex(raw, 16, 4);
        this.serverIpAddress = Utils.bytesToIPv4(Utils.readBytesFromIndex(raw, 20, 4));
        this.gatewayIpAddress = Utils.bytesToIPv4(Utils.readBytesFromIndex(raw, 24, 4));
        this.clientMacAddress = Utils.readBytesFromIndex(raw, 28, 6);
        this.clientHardwarePadding = Utils.readBytesFromIndex(raw, 34, 10);
        this.serverHostName = Utils.readBytesFromIndex(raw, 44, 64);
        this.bootFileName = Utils.readBytesFromIndex(raw, 108, 128);
        this.magicCookie = Utils.readBytesFromIndex(raw, 236, 4);

        String currRaw = Utils.readBytesFromIndex(raw, 240, ((int) udpDataLength - 240));
        DHCPOptionsCode currOption;
        // TODO while do isntead
        do {
            Option option = new Option(currRaw);
            this.optionList.add(option);
            currRaw = option.getRaw();
            currOption = DHCPOptionsCode.findDhcpOptionsCode(option.getCode());
        } while (currOption != DHCPOptionsCode.END);

        this.padding = currRaw;
        this.raw = padding;

        this.overProtocol = overProtocol;
    }

    public String getRaw() {
        return raw;
    }

    public Protocol getOverProtocol() {
        return overProtocol;
    }

    public DHCPOpCode getOpCode() {
        return opCode;
    }

    public int getHardwareType() {
        return hardwareType;
    }

    public int getAddressLength() {
        return addressLength;
    }

    public int getHops() {
        return hops;
    }

    public long getUdpDataLength() {
        return udpDataLength;
    }

    public long getTransactionId() {
        return transactionId;
    }

    public int getSecondElapsed() {
        return secondElapsed;
    }

    public String getFlagBroadcast() {
        return flagBroadcast;
    }

    public String getFlagReserved() {
        return flagReserved;
    }

    public String getClientIpAddress() {
        return clientIpAddress;
    }

    public String getYourIpAddress() {
        return yourIpAddress;
    }

    public String getServerIpAddress() {
        return serverIpAddress;
    }

    public String getGatewayIpAddress() {
        return gatewayIpAddress;
    }

    public String getClientMacAddress() {
        return clientMacAddress;
    }

    public String getClientHardwarePadding() {
        return clientHardwarePadding;
    }

    public String getServerHostName() {
        return serverHostName;
    }

    public String getBootFileName() {
        return bootFileName;
    }

    public String getMagicCookie() {
        return magicCookie;
    }

    public List<Option> getOptionList() {
        return optionList;
    }

    public String getPadding() {
        return padding;
    }
}
