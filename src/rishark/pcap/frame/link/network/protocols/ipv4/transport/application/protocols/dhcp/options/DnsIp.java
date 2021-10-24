package rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dhcp.options;

import utils.Utils;

public class DnsIp {

    private final String dnsIpAddress;

    public DnsIp(String data, int length) {
        this.dnsIpAddress = Utils.bytesToIPv4(Utils.readBytesFromIndex(data, 0, length));
    }

    public String getDnsIpAddress() {
        return dnsIpAddress;
    }
}
