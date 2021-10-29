package rishark.parser.parsers;

import rishark.pcap.frame.link.network.protocols.ipv4.transport.protocols.TransportProtocol;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.protocols.Udp;

public class UDPParser {

    private final TransportProtocol transportProtocol;

    public UDPParser(TransportProtocol udp) {
        this.transportProtocol = udp;
    }

    public void parse() {
        System.out.print("\t\tSource Port: " + ((Udp) this.transportProtocol).getSourcePort());
        System.out.println("\t\t\t\t\t\t\tDestination Port: " + ((Udp) this.transportProtocol).getDestPort());
    }
}
