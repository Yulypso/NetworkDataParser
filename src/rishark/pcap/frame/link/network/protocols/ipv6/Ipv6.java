package rishark.pcap.frame.link.network.protocols.ipv6;

import rishark.pcap.frame.link.network.protocols.NetworkProtocol;
import utils.Utils;

public class Ipv6 implements NetworkProtocol {

    private final int protocol; // nextHeader
    private final String raw;

    public Ipv6(String raw) {
        this.protocol = 1; // TODO: edit value
        this.raw = Utils.readBytesFromIndex(raw, 14, (raw.length()/2) - 14); // TODO: edit value
    }

    public int getIpProtocol() {
        return protocol;
    }

    @Override
    public String getRaw() {
        return raw;
    }
}
