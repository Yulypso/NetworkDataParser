package rishark.debug.debuggers;

import rishark.pcap.frame.link.network.protocols.ipv4.transport.protocols.TransportProtocol;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.protocols.Udp;

public class UDPDebugger {

    private final TransportProtocol transportProtocol;

    public UDPDebugger(TransportProtocol udp) {
        this.transportProtocol = udp;
    }

    public void parse() {
        System.out.println("Source Port: " + ((Udp) this.transportProtocol).getSourcePort());
        System.out.println("Destination Port: " + ((Udp) this.transportProtocol).getDestPort());
        System.out.println("Length: " + ((Udp) this.transportProtocol).getLength() + " bytes");
        System.out.println("Checksum: 0x" + ((Udp) this.transportProtocol).getChecksum());
    }
}
