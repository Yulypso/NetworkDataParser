package rishark.pcap.frame.physicalbit.linkframe;

import rishark.pcap.frame.physicalbit.EtherType;
import rishark.pcap.frame.physicalbit.linkframe.protocols.Arp;
import rishark.pcap.frame.physicalbit.linkframe.protocols.Ipv4;
import rishark.pcap.frame.physicalbit.linkframe.protocols.Ipv6;
import rishark.pcap.frame.physicalbit.linkframe.protocols.LinkProtocol;

public class LinkFrame {
    private LinkProtocol linkProtocol;

    public LinkFrame(String raw, EtherType etherType) {
        System.out.println("raw" + raw);
        System.out.println("ethertype: " + etherType);

        switch (etherType) {
            case ARP -> this.linkProtocol = new Arp(raw);
            case IPv4 -> this.linkProtocol = new Ipv4(raw);
            case IPv6 -> this.linkProtocol = new Ipv6(raw);
        }
    }

    public LinkProtocol getLinkProtocol() {
        return linkProtocol;
    }
}
