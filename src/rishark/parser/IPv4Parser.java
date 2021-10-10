package rishark.parser;

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
        System.out.println("Version: " + Objects.requireNonNull(IpVersion.findIpVersion(((Ipv4) this.networkProtocol).getVersion())).toString().replaceAll("_"," "));
        System.out.println("Header length " + ((Ipv4) this.networkProtocol).getHeaderLength() * 4 + " byte"
                + (((Ipv4) this.networkProtocol).getHeaderLength() != 0 ? "s" : ""
                + " (" + ((Ipv4) this.networkProtocol).getHeaderLength() + ")"));
        System.out.println("Type of service: " + ((Ipv4) this.networkProtocol).getTypeOfService() + " (" + this.parseTypeOfService(((Ipv4) this.networkProtocol).getTypeOfService()) + ")");
        System.out.println("Total length: " + ((Ipv4) this.networkProtocol).getTotalLength());
        System.out.println("Identification: " + ((Ipv4) this.networkProtocol).getIdentification() + " (" + Utils.hexStringToInt(((Ipv4) this.networkProtocol).getIdentification()) + ")");
        System.out.println("Flags: " + ((Ipv4) this.networkProtocol).getFlag());
    }

    private String parseTypeOfService(String b) {
        int precedence = Utils.binaryStringToInt(b.substring(0,3));
        String tos = b.substring(3,8);

        String r = null;
        switch (precedence) {
            case 0 -> r = "Routine";
            case 1 -> r = "Priority";
            case 2 -> r = "Immediate";
            case 3 -> r = "Flash";
            case 4 -> r = "Flash Over";
            case 5 -> r = "CRITIC/ECP";
            case 6 -> r = "Internetwork Control";
            case 7 -> r = "Network Control";
        }

        switch (tos) {
            case "10000" -> r += " - Minimum Delay";
            case "01000" -> r += " - Maximum throughput";
            case "00100" -> r += " - Maximum Reliability";
            case "00010" -> r += " - Minimum monetary cost";
            case "00000" -> r += " - Normal Service";
        }
        return r;
    }

    private String parseFlag(String b) {
        int reserved = Utils.binaryStringToInt(b.substring(0,1));
        int dontFragment = Utils.binaryStringToInt(b.substring(1,2));
        int moreFragment = Utils.binaryStringToInt(b.substring(2,3));

        String r = null;
        r += "\nreserved bit: " + (reserved == 1 ? "set" : "not set");
        r += "\nDon't fragment: " + (dontFragment == 1 ? "set" : "not set");
        r += "\nMore fragment: " + (moreFragment == 1 ? "set" : "not set");

        return r;
    }
}
