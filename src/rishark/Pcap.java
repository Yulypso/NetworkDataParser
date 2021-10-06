package rishark;

import rishark.headers.GlobalHeader;
import rishark.headers.PacketHeader;
import utils.PcapReader;

import java.util.List;

// Contains raw data from pcap file
public class Pcap {
    GlobalHeader globalHeader;
    List<PacketHeader> packetHeaderList;

    public Pcap(String path) {
        PcapReader pcapReader = new PcapReader(path);
        System.out.println((pcapReader.getRaw())); // raw data here

        // TODO : write globalHeader (little endian)

        // TODO : write packetHeaderList
        //this.globalHeader = new GlobalHeader();
        //this.packetHeaderList = new ArrayList<PacketHeader>();
    }

    public GlobalHeader getGlobalHeader() {
        return globalHeader;
    }

    public void setGlobalHeader(GlobalHeader globalHeader) {
        this.globalHeader = globalHeader;
    }

    public List<PacketHeader> getPacketHeaderList() {
        return packetHeaderList;
    }

    public void setPacketHeaderList(List<PacketHeader> packetHeaderList) {
        this.packetHeaderList = packetHeaderList;
    }
}
