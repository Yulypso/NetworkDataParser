package rishark;

import rishark.headers.GlobalHeader;
import rishark.headers.PacketHeader;
import utils.Utils;

import java.util.List;

// Contains raw data from pcap file
public class Pcap {
    private final boolean isBigEndian;
    private final GlobalHeader globalHeader;
    //private final List<PacketHeader> packetHeaderList;

    public Pcap(String path) {
        // TODO : write globalHeader (little endian)
        String raw = Utils.readPcap(path);
        System.out.println(raw);
        this.isBigEndian = checkIsBigEndian(Utils.toHexString(Utils.read4bytesFromIndex(raw, 0, true)));
        this.globalHeader = new GlobalHeader(raw, this.isBigEndian());

        Utils.displayHex(this.globalHeader.getMagicNumber());
        Utils.displayHex(this.globalHeader.getVersionMajor());
        Utils.displayHex(this.globalHeader.getVersionMinor());
        Utils.displayHex(this.globalHeader.getThisZone());
        Utils.displayHex(this.globalHeader.getSigFigs());
        Utils.displayHex(this.globalHeader.getSnapLen());
        Utils.displayHex(this.globalHeader.getNetwork());

        // TODO : write packetHeaderList
        //this.globalHeader = new GlobalHeader();
        //this.packetHeaderList = new ArrayList<PacketHeader>();
    }

    private boolean checkIsBigEndian(String hexMn){
        boolean isBigEndian = true;
        if (!(hexMn.equalsIgnoreCase("d4c3b2a1")) || hexMn.equalsIgnoreCase("a1b2c3d4")) {
            System.out.println("Incorrect pcap Magic Number format");
            System.exit(-1);
        } else if (hexMn.equalsIgnoreCase("d4c3b2a1")) {
            isBigEndian = false;
        }
        System.out.println("\nis big endian? : " + this.isBigEndian());
        return isBigEndian;
    }

    public GlobalHeader getGlobalHeader() {
        return globalHeader;
    }

    /*public List<PacketHeader> getPacketHeaderList() {
        return packetHeaderList;
    }
    */

    public boolean isBigEndian() {
        return isBigEndian;
    }
}
