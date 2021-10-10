package rishark.parser;

import rishark.pcap.frame.link.network.protocols.NetworkProtocol;
import rishark.pcap.frame.link.network.protocols.icmp.Icmp;

public class ICMPParser {

    NetworkProtocol networkProtocol;

    public ICMPParser (NetworkProtocol icmp) {
        this.networkProtocol = icmp;
    }

    public void parse() {
        System.out.println("ICMP Protocol: " + this.networkProtocol.getIpProtocol());
        System.out.println("ICMP Raw: " + this.networkProtocol.getRaw());
    }
}
