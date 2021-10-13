package rishark.parser;

import rishark.pcap.frame.link.EtherType;
import rishark.pcap.frame.link.protocols.arp.Arp;
import rishark.pcap.frame.link.protocols.arp.HardwareType;
import rishark.pcap.frame.link.protocols.LinkProtocol;
import rishark.pcap.frame.link.protocols.arp.OpCode;
import utils.Utils;

import java.util.Objects;


public class ARPParser {

    private final LinkProtocol linkProtocol;

    public ARPParser(LinkProtocol arp) {
        this.linkProtocol = arp;
    }

    public void parse() {
        System.out.println("Protocol type: " + HardwareType.findHardwareType(((Arp) this.linkProtocol).getHardwareType()));
        System.out.println("Protocol type: " + Objects.requireNonNull(EtherType.findEtherType(((Arp) this.linkProtocol).getProtocolType())).toString().replaceAll("_"," "));
        System.out.println("Hardware size: " + ((Arp) this.linkProtocol).getHardwareSize());
        System.out.println("Protocol size: " + ((Arp) this.linkProtocol).getProtocolSize());
        System.out.println("OpCode: " + Objects.requireNonNull(OpCode.findOpCode(((Arp) this.linkProtocol).getOpCode())).toString().replaceAll("_"," "));
        System.out.println("Sender MAC Address: " + ((Arp) this.linkProtocol).getSenderMacAddress().replaceAll("(..)(?!$)", "$1:"));
        System.out.println("Sender IP Address: " + Utils.bytesToIP(((Arp) this.linkProtocol).getSenderIpAddress()));
        System.out.println("Target MAC Address: " + ((Arp) this.linkProtocol).getTargetMacAddress().replaceAll("(..)(?!$)", "$1:"));
        System.out.println("Target IP Address: " + Utils.bytesToIP(((Arp) this.linkProtocol).getTargetIpAddress()));
        System.out.println((((Arp) this.linkProtocol).getPadding() != null) ?
                "Padding: " + ((Arp) this.linkProtocol).getPadding()
                 + " (" + ((Arp) this.linkProtocol).getPadding().length() / 2
                 + " byte" + (((Arp) this.linkProtocol).getPadding().length() / 2 != 0 ?
                 "s" : "") + ")" : "");
    }
}
