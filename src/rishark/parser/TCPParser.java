package rishark.parser;

import rishark.pcap.frame.link.network.protocols.ipv4.transport.protocols.TransportProtocol;

public class TCPParser {

    private final TransportProtocol transportProtocol;

    public TCPParser(TransportProtocol tcp) {
        this.transportProtocol = tcp;
    }

    public void parse() {
        System.out.println("TCP raw: " + this.transportProtocol.getRaw());
    }
}
