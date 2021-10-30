package rishark.parser.parsers;

import rishark.pcap.frame.link.EtherType;
import rishark.pcap.frame.link.protocols.LinkProtocol;
import rishark.pcap.frame.link.protocols.arp.Arp;
import rishark.pcap.frame.link.protocols.arp.HardwareType;
import rishark.pcap.frame.link.protocols.arp.OpCode;
import utils.Utils;

import java.util.Objects;


public class ARPParser {

    private final LinkProtocol linkProtocol;

    public ARPParser(LinkProtocol arp) {
        this.linkProtocol = arp;
    }

    public void parse() {
        System.out.print("\t\tSender MAC Address: " + ((Arp) this.linkProtocol).getSenderMacAddress());
        System.out.println("\tSender IP Address: " + Utils.bytesToIPv4(((Arp) this.linkProtocol).getSenderIpAddress()));
        System.out.print("\t\tTarget MAC Address: " + ((Arp) this.linkProtocol).getTargetMacAddress());
        System.out.println("\tTarget IP Address: " + Utils.bytesToIPv4(((Arp) this.linkProtocol).getTargetIpAddress()));
    }
}
