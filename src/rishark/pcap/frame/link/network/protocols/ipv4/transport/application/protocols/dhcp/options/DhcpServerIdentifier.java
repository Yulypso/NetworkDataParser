package rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dhcp.options;

import utils.Utils;

public class DhcpServerIdentifier {

    private final String serverIdentifierIpAddress;

    public DhcpServerIdentifier(String data, int length) {
        this.serverIdentifierIpAddress = Utils.bytesToIPv4(Utils.readBytesFromIndex(data, 0, length));
    }

    public String getServerIdentifierIpAddress() {
        return serverIdentifierIpAddress;
    }
}
