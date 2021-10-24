package rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dhcp.options;

import utils.Utils;

public class IpAddressLeaseTime implements OptionInterface {

    private final int leaseTimeSeconds; // seconds

    public IpAddressLeaseTime(String data, int length) {
        this.leaseTimeSeconds = Utils.hexStringToInt(Utils.readBytesFromIndex(data, 0, length));
    }

    public int getLeaseTimeSeconds() {
        return leaseTimeSeconds;
    }
}
