package rishark.parser.parsers;

import rishark.pcap.frame.link.network.protocols.NetworkProtocol;
import rishark.pcap.frame.link.network.protocols.ipv4.icmp.Code;
import rishark.pcap.frame.link.network.protocols.ipv4.icmp.Icmp;
import rishark.pcap.frame.link.network.protocols.ipv4.icmp.Type;
import utils.Utils;

import java.util.Objects;

public class ICMPParser {

    NetworkProtocol networkProtocol;

    public ICMPParser(NetworkProtocol icmp) {
        this.networkProtocol = icmp;
    }

    public void parse() {
        System.out.print("\t\tType: " + ((Icmp) this.networkProtocol).getType() + " [" + Type.findType(((Icmp) this.networkProtocol).getType()) + "]" + " (" + Objects.requireNonNull(Code.findCode(Type.findType(((Icmp) this.networkProtocol).getType()), ((Icmp) this.networkProtocol).getCode())).toString().replaceAll("_"," ").replaceAll("_-","").replaceAll("___","") + ")");
        System.out.print("\t\t\t\tIdentifier (BE): " + Utils.hexStringToInt(((Icmp) this.networkProtocol).getIdentifierBE()) + " (0x" + ((Icmp) this.networkProtocol).getIdentifierBE() + ")");
        System.out.println("\t\t\tSequence Number (BE): " + Utils.hexStringToInt(((Icmp) this.networkProtocol).getSequenceNumberBE()) + " (0x" + ((Icmp) this.networkProtocol).getSequenceNumberBE() + ")");
        System.out.println("\t\tTimestamp from icmp data: " + ((Icmp) this.networkProtocol).getTimeStamp());
        System.out.println("\t\tData: " + Utils.hexStringToString(((Icmp) this.networkProtocol).getData()));
    }
}
