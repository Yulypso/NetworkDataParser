package rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dhcp.options;

import utils.Utils;

public class RequestedIpAddress {

    private final String requestedIpAddress;

    public RequestedIpAddress(String data, int length) {
        this.requestedIpAddress = Utils.bytesToIPv4(Utils.readBytesFromIndex(data, 0, length));
    }

    public String getRequestedIpAddress() {
        return requestedIpAddress;
    }
}