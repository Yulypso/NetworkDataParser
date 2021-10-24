package rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dhcp.options;

import rishark.pcap.frame.link.protocols.arp.HardwareType;
import utils.Utils;

public class ClientIdentifier {

    private final HardwareType hardwareType;
    private final String macAddress;

    public ClientIdentifier(String data, int length) {
        this.hardwareType =  HardwareType.findHardwareType(Utils.hexStringToInt(Utils.readBytesFromIndex(data, 0, 1)));
        this.macAddress = Utils.bytesToMAC(Utils.readBytesFromIndex(data, 1, length-1));
    }

    public HardwareType getHardwareType() {
        return hardwareType;
    }

    public String getMacAddress() {
        return macAddress;
    }
}
