package rishark.parser.parsers;

import rishark.pcap.frame.link.network.protocols.ipv4.transport.protocols.Tcp;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.protocols.TransportProtocol;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.protocols.Udp;
import utils.Utils;

public class TCPParser {

    private final TransportProtocol transportProtocol;

    public TCPParser(TransportProtocol tcp) {
        this.transportProtocol = tcp;
    }

    public void parse() {
        System.out.print("\t\tSource Port: " + ((Tcp) this.transportProtocol).getSourcePort());
        System.out.println("\t\t\t\t\t\tDestination Port: " + ((Tcp) this.transportProtocol).getDestPort());
        System.out.print("\t\tWindow: " + ((Tcp) this.transportProtocol).getWindow() + " bytes");
        System.out.print("\t\t\t\t\t\tSequence Number: " + ((Tcp) this.transportProtocol).getSequenceNumber());
        System.out.println("\t\t\t\tAcknowledgment Number: " + ((Tcp) this.transportProtocol).getAcknowledgmentNumber());
        System.out.println(this.parseFlag(((Tcp) this.transportProtocol).getFlags()));
    }

    private String parseFlag(String b) {
        int urg = Utils.binaryStringToInt(b.substring(0, 1));
        int ack = Utils.binaryStringToInt(b.substring(1, 2));
        int push = Utils.binaryStringToInt(b.substring(2, 3));
        int reset = Utils.binaryStringToInt(b.substring(3, 4));
        int syn = Utils.binaryStringToInt(b.substring(4, 5));
        int fin = Utils.binaryStringToInt(b.substring(5, 6));

        String r = "";
        r += "\t\tUrgent: " + (urg == 1 ? "Set (1)    " : "Not set (0)");
        r += "\t\t\t\t\t\tAcknowledgment: " + (ack == 1 ? "Set (1)    " : "Not set (0)");
        r += "\n\t\tReset: " + (reset == 1 ? "Set (1)    " : "Not set (0)");
        r += "\t\t\t\t\t\tSyn: " + (syn == 1 ? "Set (1)    " : "Not set (0)");
        r += "\t\t\t\t\tFin: " + (fin == 1 ? "Set (1)    " : "Not set (0)");
        return r;
    }
}
