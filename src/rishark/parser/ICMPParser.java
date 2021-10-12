package rishark.parser;

import rishark.pcap.frame.link.network.protocols.NetworkProtocol;
import rishark.pcap.frame.link.network.protocols.ipv4.icmp.Code;
import rishark.pcap.frame.link.network.protocols.ipv4.icmp.Icmp;
import rishark.pcap.frame.link.network.protocols.ipv4.icmp.Type;
import utils.Utils;

import java.util.Objects;

public class ICMPParser {

    NetworkProtocol networkProtocol;

    public ICMPParser (NetworkProtocol icmp) {
        this.networkProtocol = icmp;
    }

    public void parse() {
        System.out.println("Type: " + ((Icmp) this.networkProtocol).getType() + " [" + Type.findType(((Icmp) this.networkProtocol).getType()) + "]" + " (" + Objects.requireNonNull(Code.findCode(Type.findType(((Icmp) this.networkProtocol).getType()), ((Icmp) this.networkProtocol).getCode())).toString().replaceAll("_"," ").replaceAll("_-","").replaceAll("___","") + ")");
        System.out.println("Checksum: 0x" + ((Icmp) this.networkProtocol).getChecksum());
        System.out.println("Identifier (BE): " + Utils.hexStringToInt(((Icmp) this.networkProtocol).getIdentifierBE()) + " (0x" + ((Icmp) this.networkProtocol).getIdentifierBE() + ")");
        System.out.println("Identifier (LE): " + Utils.hexStringToInt(((Icmp) this.networkProtocol).getIdentifierLE()) + " (0x" + ((Icmp) this.networkProtocol).getIdentifierLE() + ")");
        System.out.println("Sequence Number (BE): " + Utils.hexStringToInt(((Icmp) this.networkProtocol).getSequenceNumberBE()) + " (0x" + ((Icmp) this.networkProtocol).getSequenceNumberBE() + ")");
        System.out.println("Sequence Number (LE): " + Utils.hexStringToInt(((Icmp) this.networkProtocol).getSequenceNumberLE()) + " (0x" + ((Icmp) this.networkProtocol).getSequenceNumberLE() + ")");
        System.out.println("Timestamp from icmp data: " + ((Icmp) this.networkProtocol).getTimeStamp());
        System.out.println("Data: " + Utils.hexStringToString(((Icmp) this.networkProtocol).getData()));
    }
}
