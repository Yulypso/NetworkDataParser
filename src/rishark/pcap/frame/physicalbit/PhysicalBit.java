package rishark.pcap.frame.physicalbit;

import rishark.pcap.frame.physicalbit.linkframe.LinkFrame;
import utils.Utils;

public class PhysicalBit {

    private LinkFrame linkFrame;

    private final String srcAdress;     // 6 bytes
    private final String destAdress;    // 6 bytes
    private final String etherType;     // 2 bytes

    private final String raw;

    public PhysicalBit(String raw) {
        this.destAdress = Utils.readBytesFromIndex(raw, 0, 6);
        this.srcAdress = Utils.readBytesFromIndex(raw, 6, 6);
        this.etherType = Utils.readBytesFromIndex(raw, 12, 2);

        this.raw = Utils.readBytesFromIndex(raw, 14, (raw.length()/2) - 14);

        EtherType e;
        if ((e = EtherType.findEtherType(this.etherType)) == null) {
            /* Only IPv4, IPv6 and ARP are treated */
            System.out.println("EtherType is Untreated.");
        } else {
            /* Continue decapsulation */
            this.linkFrame = new LinkFrame(this.raw, e);
        }
    }

    public String getSrcAdress() {
        return srcAdress;
    }

    public String getDestAdress() {
        return destAdress;
    }

    public String getEtherType() {
        return etherType;
    }

    public String getRaw() {
        return raw;
    }

    public LinkFrame getLinkFrame() {
        return linkFrame;
    }
}
