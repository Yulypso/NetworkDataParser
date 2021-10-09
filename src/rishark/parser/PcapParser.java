package rishark.parser;

import rishark.pcap.Pcap;
import rishark.pcap.frame.link.EtherType;
import rishark.pcap.frame.link.network.protocols.NetworkProtocol;
import rishark.pcap.frame.link.protocols.Arp;
import utils.Utils;

import java.util.Arrays;
import java.util.Calendar;
import java.util.Objects;

public class PcapParser {

    private final Pcap pcap;

    public PcapParser(Pcap pcap) {
        this.pcap = pcap;
    }

    public void numberOfFrames() {
        System.out.println("Total number of frames: " + this.pcap.getFrameList().size());
    }

    public void parseGlobalHeader() {
        System.out.println("\n--- [GlobalHeader] ---");
        System.out.println("Magic number: " + Utils.toHexString(this.pcap.getGlobalHeader().getMagicNumber()));
        System.out.println("Major version number: " + this.pcap.getGlobalHeader().getVersionMajor());
        System.out.println("Minor version number: " + this.pcap.getGlobalHeader().getVersionMinor());
        System.out.println("GMT to local correction: " + this.pcap.getGlobalHeader().getThisZone());
        System.out.println("Accuracy of timestamps: " + this.pcap.getGlobalHeader().getSigFigs());
        System.out.println("Max length of captured packets in bytes: " + this.pcap.getGlobalHeader().getSnapLen());
        System.out.println("Data link type: " + (this.pcap.getGlobalHeader().getNetwork() == 1 ? "1 [Ethernet]" : (this.pcap.getGlobalHeader().getNetwork() + " [Not Ethernet, Untreated]")));
    }

    public void parseFrame(int... selected) { /* First frame is at index 0 */

        for (int s : selected) {
            s--;
            System.out.println("\n******** [Frame n°" + (s+1) + "] ********");
            System.out.println("***** [Frame Header] *****");
            System.out.println("--- [Physical layer Bits] ---");
            this.parseFrameHeader(s);
            System.out.println("***** [Frame Data] *****");
            System.out.println("--- [Data Link layer Frame ] ---");
            if (this.parseLinkFrame(s))
                continue;
            System.out.println("--- [Network layer Packet] ---");
            //this.parseNetworkPacket(s);
            System.out.println("--- [Transport layer Segment/Datagram ] ---");
            //this.parseTransportSegment(s);
        }
    }

    private void parseFrameHeader(int s) {
        /* Physical layer (bits) (equivalent to packet header in Wireshark) */
        Calendar c = Calendar.getInstance();
        String reformat = "" + this.pcap.getFrameList().get(s).getPacketHeader().getTsSec() + "000";
        c.setTimeInMillis(Long.parseLong(reformat, 10));
        System.out.println("Timestamp in seconds: " + this.pcap.getFrameList().get(s).getPacketHeader().getTsSec() + " [" + c.getTime() + "]");
        System.out.println("Timestamp in microseconds: " + this.pcap.getFrameList().get(s).getPacketHeader().getTsUsec());
        System.out.println("Number of octets of packet saved in file: " + this.pcap.getFrameList().get(s).getPacketHeader().getInclLen());
        System.out.println("Actual length of packet: " + this.pcap.getFrameList().get(s).getPacketHeader().getOrigLen());
    }

    private boolean parseLinkFrame(int s) {
        /* Data Link layer (Data Frames) */
        System.out.println("Destination MAC address: " + this.pcap.getFrameList().get(s).getLinkFrame().getDestAdress().replaceAll("(..)(?!$)", "$1:"));
        System.out.println("Source MAC address: " + this.pcap.getFrameList().get(s).getLinkFrame().getSrcAdress().replaceAll("(..)(?!$)", "$1:"));
        EtherType e = EtherType.findEtherType(this.pcap.getFrameList().get(s).getLinkFrame().getEtherType());
        System.out.println("Ether type: " + e);

        switch (Objects.requireNonNull(e)) {
            case ARP -> {
                new ArpParser(this.pcap.getFrameList().get(s).getLinkFrame().getLinkProtocol()).parse();
                return (this.pcap.getFrameList().get(s).getPacketHeader().getOrigLen() == this.pcap.getFrameList().get(s).getLinkFrame().getLinkFrameSize()); // End of frame, no more layer above ARP
            }
        }
        //System.out.println("Parse Network Packet: " + Arrays.toString(new int[]{this.pcap.getFrameList().get(s).getLinkFrame().getNetworkPacket().getNetworkProtocol().getClass().getDeclaredMethods().length}));
        return false;
    }

    private void parseNetworkPacket(int s) {
        /* Network layer (Data Frames) */
        System.out.println("Parse Network Packet: " + Arrays.toString(new int[]{this.pcap.getFrameList().get(s).getLinkFrame().getNetworkPacket().getNetworkProtocol().getClass().getDeclaredMethods().length}));
        System.out.println("Parse Network class: " + this.pcap.getFrameList().get(s).getLinkFrame().getNetworkPacket().getNetworkProtocol().getClass().equals(NetworkProtocol.class));

    }

    private void parseTransportSegment(int s) {
        /* Transport layer (Transport Segments or Datagrams) */
    }
}
