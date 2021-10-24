package rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dhcp.options;

import utils.Utils;

public class RenewalTimeValue implements OptionInterface {

    private final int renewalTimeSeconds; // seconds

    public RenewalTimeValue(String data, int length) {
        this.renewalTimeSeconds = Utils.hexStringToInt(Utils.readBytesFromIndex(data, 0, length));
    }

    public int getRenewalTimeSeconds() {
        return renewalTimeSeconds;
    }
}
