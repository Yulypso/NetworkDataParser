package rishark.pcap.frame.link.network;

import rishark.pcap.frame.link.EtherType;
import rishark.pcap.frame.link.network.protocols.ipv4.icmp.Icmp;
import rishark.pcap.frame.link.network.protocols.ipv4.Ipv4;
import rishark.pcap.frame.link.network.protocols.NetworkProtocol;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.TransportSegment;

import java.util.Objects;

public class NetworkPacket {

    private NetworkProtocol networkProtocol; // ICPM
    private TransportSegment transportSegment;

    /* Base */
    private NetworkProtocol networkProtocolBase; // IPv4, IPv6

    private int ipProtocol;
    private String raw;

    public NetworkPacket(String raw, EtherType etherType) {
        switch (etherType) {
            case IPv4 -> {
                this.networkProtocolBase = new Ipv4(raw);

                this.ipProtocol = Objects.requireNonNull(this.networkProtocolBase).getIpProtocol();
                this.raw = this.networkProtocolBase.getRaw();

                Protocol i;
                if ((i = Protocol.findProtocol(this.getIpProtocol())) == null) {
                    System.out.println("IP Protocol untreated.");
                } else {
                    switch (i) {
                        case ICMP -> this.networkProtocol = new Icmp(this.raw);
                        default -> this.transportSegment = new TransportSegment(this.raw, i);
                    }
                }
            }
            case IPv6 -> {} //this.networkProtocolBase = new Ipv6(raw);
        }
    }

    public NetworkProtocol getNetworkProtocol() {
        return networkProtocol;
    }

    public NetworkProtocol getNetworkProtocolBase() {
        return networkProtocolBase;
    }

    public TransportSegment getTransportSegment() {
        return transportSegment;
    }

    public int getIpProtocol() {
        return ipProtocol;
    }

    public String getRaw() {
        return raw;
    }

    public long getNetworkPacketSize() {
        return this.networkProtocolBase.getSize() + this.networkProtocol.getSize();
    }
}
