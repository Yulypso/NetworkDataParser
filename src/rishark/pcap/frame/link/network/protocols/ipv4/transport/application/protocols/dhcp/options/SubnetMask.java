package rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dhcp.options;

import utils.Utils;

public class SubnetMask implements OptionInterface {

    private final String subnetMask;

    public SubnetMask(String data, int length) {
        this.subnetMask = Utils.bytesToIPv4(Utils.readBytesFromIndex(data, 0, length));
    }

    public String getSubnetMask() {
        return subnetMask;
    }
}
