package rishark.pcap;

import rishark.pcap.header.GlobalHeader;
import rishark.pcap.physicalbit.PhysicalBit;
import utils.Utils;

import java.util.ArrayList;
import java.util.List;

// Contains raw data from pcap file
public class Pcap {
    private final boolean isBigEndian;
    private final GlobalHeader globalHeader;
    private final List<PhysicalBit> physicalBitList;


    public Pcap(String path) {

        /* GlobalHeader */
        String raw = Utils.readPcap(path);
        System.out.println(raw);
        this.isBigEndian = checkIsBigEndian(Utils.readBytesFromIndex(raw, 0, 4,true));
        this.globalHeader = new GlobalHeader(raw, this.isBigEndian());


        /* physicalBitList */
        long pcapLength = raw.length() / 2;
        System.out.println("raw length (bytes): " + pcapLength);
        int currentPos = this.globalHeader.getLength();
        this.physicalBitList = new ArrayList<>();

        while (currentPos != pcapLength) {
            PhysicalBit physicalBit = new PhysicalBit(raw, currentPos, this.isBigEndian());
            this.physicalBitList.add(physicalBit);
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

    public List<PhysicalBit> getPhysicalBitList() {
        return physicalBitList;
    }
}
