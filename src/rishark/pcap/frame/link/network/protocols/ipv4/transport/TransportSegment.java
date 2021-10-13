package rishark.pcap.frame.link.network.protocols.ipv4.transport;

import rishark.pcap.frame.link.network.Protocol;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.protocols.Tcp;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.protocols.TransportProtocol;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.protocols.Udp;

public class TransportSegment {

    private TransportProtocol transportProtocolBase; // TCP,

    private String raw;

    public TransportSegment (String raw, Protocol ipProtocol) {
        switch (ipProtocol) {
            case TCP -> {
                this.transportProtocolBase = new Tcp(raw);
                this.raw = this.transportProtocolBase.getRaw();
            }
            case UDP -> {
                this.transportProtocolBase = new Udp(raw);
                this.raw = this.transportProtocolBase.getRaw();
            }
        }
    }

    public TransportProtocol getTransportProtocolBase() {
        return transportProtocolBase;
    }

    public String getRaw() {
        return raw;
    }
}
