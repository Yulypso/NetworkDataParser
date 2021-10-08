package rishark.parser;

import rishark.pcap.Pcap;
import utils.Utils;

import java.text.ParseException;
import java.util.Calendar;
import java.util.Date;

public class PcapParser {

    private final Pcap pcap;

    public PcapParser(Pcap pcap) {
        this.pcap = pcap;
    }

    public void numberOfFrames() {
        System.out.println("Total number of frames: " + this.pcap.getPhysicalBitList().size());
    }

    public void parseGlobalHeader() {
        System.out.println("--- [GlobalHeader] ---");
        System.out.println("Magic number: " + Utils.toHexString(this.pcap.getGlobalHeader().getMagicNumber()));
        System.out.println("Major version number: " + this.pcap.getGlobalHeader().getVersionMajor());
        System.out.println("Minor version number: " + this.pcap.getGlobalHeader().getVersionMinor());
        System.out.println("GMT to local correction: " + this.pcap.getGlobalHeader().getThisZone());
        System.out.println("Accuracy of timestamps: " + this.pcap.getGlobalHeader().getSigFigs());
        System.out.println("Max length of captured packets in bytes: " + this.pcap.getGlobalHeader().getSnapLen());
        System.out.println("Data link type: " + (this.pcap.getGlobalHeader().getNetwork() == 1 ? "1 [Ethernet]" : (this.pcap.getGlobalHeader().getNetwork() + " [Not Ethernet, Untreated]")));
    }

    public void parseFrame(int... selected) { /* First frame is at index 0 */
        Calendar c = Calendar.getInstance();

        for (int s : selected) {
            System.out.println("--- [Frame" + s + "] ---");
            String reformat = "" + this.pcap.getPhysicalBitList().get(s).getPhysicalBitHeader().getTsSec() + "000";
            c.setTimeInMillis(Long.parseLong(reformat, 10));
            System.out.println("Timestamp in seconds: " + this.pcap.getPhysicalBitList().get(s).getPhysicalBitHeader().getTsSec() + " [" + c.getTime() + "]");
            System.out.println("Timestamp in microseconds: " + this.pcap.getPhysicalBitList().get(s).getPhysicalBitHeader().getTsUsec());
            System.out.println("Number of octets of packet saved in file: " + this.pcap.getPhysicalBitList().get(s).getPhysicalBitHeader().getInclLen());
            System.out.println("Actual length of packet: " + this.pcap.getPhysicalBitList().get(s).getPhysicalBitHeader().getOrigLen());
        }
    }
}
