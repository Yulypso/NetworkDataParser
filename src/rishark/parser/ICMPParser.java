package rishark.parser;

import rishark.pcap.frame.link.network.protocols.NetworkProtocol;
import rishark.pcap.frame.link.network.protocols.icmp.Code;
import rishark.pcap.frame.link.network.protocols.icmp.Icmp;
import rishark.pcap.frame.link.network.protocols.icmp.Type;

import java.util.Objects;

public class ICMPParser {

    NetworkProtocol networkProtocol;

    public ICMPParser (NetworkProtocol icmp) {
        this.networkProtocol = icmp;
    }

    public void parse() {
        System.out.println("ICMP Protocol: " + this.networkProtocol.getIpProtocol());
        //System.out.println("ICMP Raw: " + this.networkProtocol.getRaw());
        System.out.println("Type: " + ((Icmp) this.networkProtocol).getType() + " [" + Type.findType(((Icmp) this.networkProtocol).getType()) + "]" + " (" + Objects.requireNonNull(Code.findCode(Type.findType(((Icmp) this.networkProtocol).getType()), ((Icmp) this.networkProtocol).getCode())).toString().replaceAll("_"," ").replaceAll("_-","").replaceAll("___","") + ")");
        // TODO: start from Checksum

        System.out.println(((Icmp) this.networkProtocol).getData());
    }
}
