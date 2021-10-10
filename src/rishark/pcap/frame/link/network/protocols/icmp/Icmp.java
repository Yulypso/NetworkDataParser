package rishark.pcap.frame.link.network.protocols.icmp;

import rishark.pcap.frame.link.network.protocols.IpProtocol;
import rishark.pcap.frame.link.network.protocols.NetworkProtocol;
import rishark.pcap.frame.link.network.transport.protocols.TransportProtocol;

// TODO: Parse ICMP + verify if padding for PcapParser with continue
public class Icmp implements NetworkProtocol {

    private final String raw;

    public Icmp (String raw) {
        this.raw = raw; // TODO: edit value (test)
    }

    @Override // TODO: edit value
    public int getIpProtocol() {
        return IpProtocol.ICMP.getProtocol();
    }

    public String getRaw() {
        return raw;
    }
}
