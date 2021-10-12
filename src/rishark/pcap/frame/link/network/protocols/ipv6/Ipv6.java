package rishark.pcap.frame.link.network.protocols.ipv6;

import rishark.pcap.frame.link.network.IpProtocol;
import rishark.pcap.frame.link.network.protocols.NetworkProtocol;
import utils.Utils;

public class Ipv6 implements NetworkProtocol {

    private final int protocol; // nextHeader
    private final String raw;

    public Ipv6(String raw) {
        this.protocol = IpProtocol.IPv4.getProtocol(); // TODO: edit value
        this.raw = Utils.readBytesFromIndex(raw, 48, (raw.length()/2) - 48); // TODO: edit value
    }

    @Override
    public long getSize() {
        return 48;
    }

    public int getIpProtocol() {
        return protocol;
    }

    @Override
    public String getRaw() {
        return raw;
    }
}
