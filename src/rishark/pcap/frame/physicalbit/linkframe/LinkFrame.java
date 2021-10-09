package rishark.pcap.frame.physicalbit.linkframe;

import rishark.pcap.frame.physicalbit.EtherType;

public class LinkFrame {


    public LinkFrame(String raw, EtherType etherType) {
        System.out.println("raw" + raw);
        System.out.println("ethertype" + etherType);
    }
}
