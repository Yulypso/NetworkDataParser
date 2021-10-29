package rishark.parser;

import rishark.pcap.Pcap;
import rishark.pcap.frame.link.EtherType;
import rishark.pcap.frame.link.network.Protocol;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.AppProtocol;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.ApplicationProtocol;
import utils.Utils;

import java.util.Calendar;
import java.util.Objects;
import java.util.stream.IntStream;

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

    public void parseFrame(int... selected) {
        if (selected.length < 1) {
            this.parseFrame(IntStream.range(1, this.pcap.getFrameList().size() + 1).toArray());
        } else {
            for (int s : selected) { /* Parse selected frames */
                try {
                    if (s < 1 || s > this.pcap.getFrameList().size()) {
                        throw new Exception();
                    } else {

                        try{
                            s--; // test
                            System.out.println("\n******** [Frame n°" + (s + 1) + "] ********");
                            System.out.println("***** [Frame Header] *****");
                            System.out.println("--- [Physical layer Bits] ---");
                            this.parseFrameHeader(s);
                            System.out.println("***** [Frame Data] *****");
                            System.out.println("--- [Data Link layer Frame] ---");
                            if (this.parseLinkFrame(s))
                                continue;
                            System.out.println("--- [Network layer Packet] ---");
                            if(this.parseNetworkPacket(s))
                                continue;
                            System.out.println("--- [Transport layer Segment/Datagram] ---");
                            if(this.parseTransportSegment(s))
                                continue;
                            System.out.println("--- [Application layer Rishar] ---");
                            this.parseApplicationRishar(s);
                        } catch (Exception e) {
                            System.err.println("\nWarning: Frame n°" + (s+1) + " protocol not implemented. Skipping it...");
                        }
                    }
                } catch (Exception e) {
                    System.err.println("\nError: Frame n°" + s + " doesn't exist. Skipping it...");
                }
            }
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
        EtherType e;
        if ((e = EtherType.findEtherType(this.pcap.getFrameList().get(s).getLinkFrame().getEtherType())) != null) {
            System.out.println("Ether type: " + e);

            switch (Objects.requireNonNull(e)) {
                case ARP -> {
                    new ARPParser(this.pcap.getFrameList().get(s).getLinkFrame().getLinkProtocol()).parse();
                    return (this.pcap.getFrameList().get(s).getPacketHeader().getOrigLen() ==
                            this.pcap.getFrameList().get(s).getLinkFrame().getLinkFrameSize()); // End of frame, no more layer above ARP
                }
                default -> {return false;}
            }
        } else {
            System.out.println("Ether type: Unknown");
            return true;
        }
    }

    private boolean parseNetworkPacket(int s) {
        /* Network layer (Data Frames) */
        EtherType e = EtherType.findEtherType(this.pcap.getFrameList().get(s).getLinkFrame().getEtherType());
        switch (Objects.requireNonNull(e)) {
            case IPv4 -> new IPv4Parser(this.pcap.getFrameList().get(s).getLinkFrame().getNetworkPacket().getNetworkProtocolBase()).parse();
            case IPv6 -> {return true;}
            default -> {return true;}
        }

        Protocol p = Protocol.findProtocol(this.pcap.getFrameList().get(s).getLinkFrame().getNetworkPacket().getIpProtocol());
        switch (Objects.requireNonNull(p)) {
            case ICMP -> {
                new ICMPParser(this.pcap.getFrameList().get(s).getLinkFrame().getNetworkPacket().getNetworkProtocol()).parse();
                return (this.pcap.getFrameList().get(s).getLinkFrame().getNetworkPacket().getNetworkProtocol().getRaw().length() == 0); // End of packet, no more layer above ICMP
            }
            case IGMP -> {return true;}
            default -> {return false;}
        }
    }

    private boolean parseTransportSegment(int s) {
        /* Transport layer (Transport Segments or Datagrams) */
        Protocol p = Protocol.findProtocol(this.pcap.getFrameList().get(s).getLinkFrame().getNetworkPacket().getIpProtocol());
        switch (Objects.requireNonNull(p)) {
            case TCP -> {
                new TCPParser(this.pcap.getFrameList().get(s).getLinkFrame().getNetworkPacket().getTransportSegment().getTransportProtocolBase()).parse();
                return (this.pcap.getFrameList().get(s).getLinkFrame().getNetworkPacket().getTransportSegment().getTransportProtocolBase().getRaw().length() == 0);
            }
            case UDP -> {
                new UDPParser(this.pcap.getFrameList().get(s).getLinkFrame().getNetworkPacket().getTransportSegment().getTransportProtocolBase()).parse();
                return (this.pcap.getFrameList().get(s).getLinkFrame().getNetworkPacket().getTransportSegment().getTransportProtocolBase().getRaw().length() == 0);
            }
            default -> {return false;}
        }
    }

    private void parseApplicationRishar(int s) {
        /* Application layer */
        AppProtocol ap = this.pcap.getFrameList().get(s).getLinkFrame().getNetworkPacket().getTransportSegment().getAppProtocol();
        if (ap != null) {
            switch (ap) {
                case FTP -> new FTPParser(this.pcap.getFrameList().get(s).getLinkFrame().getNetworkPacket().getTransportSegment().getApplicationRishar().getApplicationProtocol()).parse();
                case DNS -> new DNSParser(this.pcap.getFrameList().get(s).getLinkFrame().getNetworkPacket().getTransportSegment().getApplicationRishar().getApplicationProtocol()).parse();
                case DHCP -> new DHCPParser(this.pcap.getFrameList().get(s).getLinkFrame().getNetworkPacket().getTransportSegment().getApplicationRishar().getApplicationProtocol()).parse();
                case HTTP -> new HTTPParser(this.pcap.getFrameList().get(s).getLinkFrame().getNetworkPacket().getTransportSegment().getApplicationRishar().getApplicationProtocol()).parse();
            }
        } else {
            System.out.println("Unknown protocol raw: " + this.pcap.getFrameList().get(s).getLinkFrame().getNetworkPacket().getTransportSegment().getTransportProtocolBase().getRaw());
        }
    }
}
