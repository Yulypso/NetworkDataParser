package rishark.parser.parsers;

import rishark.pcap.frame.link.network.Protocol;
import rishark.pcap.frame.link.network.protocols.NetworkProtocol;
import rishark.pcap.frame.link.network.protocols.ipv4.IpVersion;
import rishark.pcap.frame.link.network.protocols.ipv4.Ipv4;
import utils.Utils;

import java.util.Objects;

public class IPv4Parser {

    private final NetworkProtocol networkProtocol;

    public IPv4Parser(NetworkProtocol ipv4) {
        this.networkProtocol = ipv4;
    }

    public void parse() {
        System.out.print("\t\t" + this.parseFlag(((Ipv4) this.networkProtocol).getFlag()));
        System.out.println("\t\t\t\tIdentification: 0x" + ((Ipv4) this.networkProtocol).getIdentification() + " (" + Utils.hexStringToInt(((Ipv4) this.networkProtocol).getIdentification()) + ")");
        System.out.print("\t\tFragment offset: " + ((Ipv4) this.networkProtocol).getFragmentOffset());
        System.out.println("\t\t\t\t\t\tSource IP Address: " + ((Ipv4) this.networkProtocol).getSrcAddress());
        System.out.print("\t\tProtocol: " + Objects.requireNonNull(Protocol.findProtocol(this.networkProtocol.getIpProtocol())).toString().replaceAll("_"," "));
        System.out.println("\t\t\t\t\t\t\tDestination IP Address: " + ((Ipv4) this.networkProtocol).getDestAddress());
    }

    private String parseFlag(String b) {
        int reserved = Utils.binaryStringToInt(b.substring(0,1));
        int dontFragment = Utils.binaryStringToInt(b.substring(1,2));
        int moreFragment = Utils.binaryStringToInt(b.substring(2,3));

        String r = "";
        r += "Don't fragment: " + (dontFragment == 1 ? "Set (1)    " : "Not set (0)");
        r += "\t\t\t\t\tMore fragment: " + (moreFragment == 1 ? "Set (1)    " : "Not set (0)");
        return r;
    }
}
