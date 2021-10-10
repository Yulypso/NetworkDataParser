package rishark.pcap.frame.link.network;

import rishark.pcap.frame.link.Protocol;
import rishark.pcap.frame.link.network.protocols.ipv4.Ipv4;
import rishark.pcap.frame.link.network.protocols.ipv6.Ipv6;
import rishark.pcap.frame.link.network.protocols.NetworkProtocol;

public class NetworkPacket {
    private NetworkProtocol networkProtocol;

    public NetworkPacket(String raw, Protocol etherType) {
        switch (etherType) {
            case IPv4 -> this.networkProtocol = new Ipv4(raw);
            case IPv6 -> this.networkProtocol = new Ipv6(raw);
        }

        // TODO: switch case for ICMP adaptive IPv4 and IPv6
    }

    public NetworkProtocol getNetworkProtocol() {
        return networkProtocol;
    }
}
