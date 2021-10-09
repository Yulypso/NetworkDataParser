package rishark.parser;

import rishark.pcap.Pcap;
import rishark.pcap.frame.physicalbit.EtherType;
import utils.Utils;

import java.util.Calendar;

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
        /* Physical scope (bits) */

        for (int s : selected) {
            s--;
            System.out.println("\n******** [Frame n°" + (s+1) + "] ********");
            System.out.println("***** [Frame Header] *****");
            this.parseFrameHeader(s);
            System.out.println("***** [Frame Data] *****");
            System.out.println("--- [Physical Bit scope] ---");
            this.parsePhysicalBit(s);
            System.out.println("--- [Data Link Frame scope] ---");
            //this.parseLinkFrame(s);
            System.out.println("--- [Network Packet scope] ---");
            //this.parseNetworkPacket(s);
            System.out.println("--- [Transport Segment/Datagram scope] ---");
            //this.parseTransportSegment(s);
        }
    }

    private void parseFrameHeader(int s) {
        /* Equivalent to Packet Header in Wireshark documentation */
        Calendar c = Calendar.getInstance();
        String reformat = "" + this.pcap.getFrameList().get(s).getPacketHeader().getTsSec() + "000";
        c.setTimeInMillis(Long.parseLong(reformat, 10));
        System.out.println("Timestamp in seconds: " + this.pcap.getFrameList().get(s).getPacketHeader().getTsSec() + " [" + c.getTime() + "]");
        System.out.println("Timestamp in microseconds: " + this.pcap.getFrameList().get(s).getPacketHeader().getTsUsec());
        System.out.println("Number of octets of packet saved in file: " + this.pcap.getFrameList().get(s).getPacketHeader().getInclLen());
        System.out.println("Actual length of packet: " + this.pcap.getFrameList().get(s).getPacketHeader().getOrigLen());
    }

    private void parsePhysicalBit(int s) {
        /* Physical scope (bits) */
        System.out.println("Destination MAC address: " + this.pcap.getFrameList().get(s).getPhysicalBit().getDestAdress());
        System.out.println("Source MAC address: " + this.pcap.getFrameList().get(s).getPhysicalBit().getSrcAdress());
        System.out.println("Protocol type: " + EtherType.findEtherType(this.pcap.getFrameList().get(s).getPhysicalBit().getEtherType()));
    }

    private void parseLinkFrame(int s) {
        /* Data Link scope (Data Frames) */
    }

    private void parseNetworkPacket(int s) {
        /* Data Link scope (Network Packets) */
    }

    private void parseTransportSegment(int s) {
        /* Data Link scope (Transport Segments or Datagrams) */
    }
}
