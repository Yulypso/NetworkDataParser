package rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dhcp.options;

import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dhcp.Option;
import utils.Utils;

public class RequestedIpAddress implements OptionInterface {

    private final String requestedIpAddress;

    public RequestedIpAddress(String data, int length) {
        this.requestedIpAddress = Utils.bytesToIPv4(Utils.readBytesFromIndex(data, 0, length));
    }

    public String getRequestedIpAddress() {
        return requestedIpAddress;
    }
}