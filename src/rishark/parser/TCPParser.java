package rishark.parser;

import rishark.pcap.frame.link.network.protocols.ipv4.transport.protocols.Tcp;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.protocols.TransportProtocol;
import utils.Utils;

public class TCPParser {

    private final TransportProtocol transportProtocol;

    public TCPParser(TransportProtocol tcp) {
        this.transportProtocol = tcp;
    }

    public void parse() {
        System.out.println("Source Port: " + ((Tcp) this.transportProtocol).getSourcePort());
        System.out.println("Destination Port: " + ((Tcp) this.transportProtocol).getDestPort());
        System.out.println("Sequence Number: " + ((Tcp) this.transportProtocol).getSequenceNumber());
        System.out.println("Acknowledgment Number: " + ((Tcp) this.transportProtocol).getAcknowledgmentNumber());
        System.out.println("Header length: " + ((Tcp) this.transportProtocol).getHeaderLength() + " bytes");
        System.out.println("Reserved: " + this.parseReservedFlag(((Tcp) this.transportProtocol).getReserved()));
        System.out.println("Flags: " + this.parseFlag(((Tcp) this.transportProtocol).getFlags()));
        System.out.println("Window: " + ((Tcp) this.transportProtocol).getWindow() + " bytes");
        System.out.println("Checksum: 0x" + ((Tcp) this.transportProtocol).getChecksum());
        System.out.println("Urgent pointer: " + ((Tcp) this.transportProtocol).getUrgentPointer());
        if (((Tcp) this.transportProtocol).getOptions().length() > 0)
            System.out.println("Options: " + ((Tcp) this.transportProtocol).getOptions());
        if (this.transportProtocol.getRaw().length() > 0)
            System.out.println("TCP segment data: \n" + this.transportProtocol.getRaw());
    }

    private String parseReservedFlag(String b) {
        String reserved = b.substring(0, 3);
        int ecn = Utils.binaryStringToInt(b.substring(3, 4));
        int cwr = Utils.binaryStringToInt(b.substring(4, 5));
        int ece = Utils.binaryStringToInt(b.substring(5, 6));

        String r = "" + reserved + ecn + " " + cwr + ece + "..";
        r += "\n\t- Reserved bits: " + reserved;
        r += "\n\t- ECN (Nonce): " + (ecn == 1 ? "Set (1)" : "Not set (0)");
        r += "\n\t- CWR (Congestion Window Reduced): " + (cwr == 1 ? "Set (1)" : "Not set (0)");
        r += "\n\t- ECE (ECN-Echo): " + (ece == 1 ? "Set (1)" : "Not set (0)");
        return r;
    }
    private String parseFlag(String b) {
        int urg = Utils.binaryStringToInt(b.substring(0, 1));
        int ack = Utils.binaryStringToInt(b.substring(1, 2));
        int push = Utils.binaryStringToInt(b.substring(2, 3));
        int reset = Utils.binaryStringToInt(b.substring(3, 4));
        int syn = Utils.binaryStringToInt(b.substring(4, 5));
        int fin = Utils.binaryStringToInt(b.substring(5, 6));

        String r = ".." + urg + ack + " " + push + reset + syn + fin;
        r += "\n\t- Urgent: " + (urg == 1 ? "Set (1)" : "Not set (0)");
        r += "\n\t- Acknowledgment: " + (ack == 1 ? "Set (1)" : "Not set (0)");
        r += "\n\t- Push: " + (push == 1 ? "Set (1)" : "Not set (0)");
        r += "\n\t- Reset: " + (reset == 1 ? "Set (1)" : "Not set (0)");
        r += "\n\t- Syn: " + (syn == 1 ? "Set (1)" : "Not set (0)");
        r += "\n\t- Fin: " + (fin == 1 ? "Set (1)" : "Not set (0)");
        return r;
    }
}
