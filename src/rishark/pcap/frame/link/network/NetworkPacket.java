package rishark.pcap.frame.link.network;

import rishark.pcap.frame.link.EtherType;
import rishark.pcap.frame.link.network.protocols.Ipv4;
import rishark.pcap.frame.link.network.protocols.Ipv6;
import rishark.pcap.frame.link.network.protocols.NetworkProtocol;

public class NetworkPacket {
    private NetworkProtocol networkProtocol;

    public NetworkPacket(String raw, EtherType etherType) {
        System.out.println("raw" + raw);
        System.out.println("ethertype: " + etherType);

        switch (etherType) {
            case IPv4 -> this.networkProtocol = new Ipv4(raw);
            case IPv6 -> this.networkProtocol = new Ipv6(raw);
        }
    }

    public NetworkProtocol getNetworkProtocol() {
        return networkProtocol;
    }
}
