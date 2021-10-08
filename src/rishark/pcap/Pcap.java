package rishark.pcap;

import rishark.pcap.frames.Frame;
import utils.Utils;

import java.util.ArrayList;
import java.util.List;

// Contains raw data from pcap file
public class Pcap {
    private final boolean isBigEndian;
    private final GlobalHeader globalHeader;
    private final List<Frame> frameList;


    public Pcap(String path) {

        /* GlobalHeader */
        String raw = Utils.readPcap(path);
        System.out.println(raw);
        this.isBigEndian = checkIsBigEndian(Utils.readBytesFromIndex(raw, 0, 4,true));
        this.globalHeader = new GlobalHeader(raw, this.isBigEndian());

        if (this.globalHeader.getNetwork() != 1){
            System.out.println("Data link type is not Ethernet, Untreated.");
            System.exit(-1);
        }

        /* physicalBitList */
        long pcapLength = raw.length() / 2;
        System.out.println("raw length (bytes): " + pcapLength);
        int currentPos = this.globalHeader.getLength();
        this.frameList = new ArrayList<>();

        while (currentPos != pcapLength) {
            Frame physicalBit = new Frame(raw, currentPos, this.isBigEndian());
            this.frameList.add(physicalBit);
            currentPos = physicalBit.getLastPos();
            //System.out.println("curr pos: " + pos);
        }
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

    public boolean isBigEndian() {
        return isBigEndian;
    }

    public List<Frame> getFrameList() {
        return frameList;
    }
}
