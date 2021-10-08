package rishark;

import rishark.parser.PcapParser;
import rishark.pcap.Pcap;

public class RiShark {

    public static void main(String[] args) {

        if (args.length != 1) {
            System.out.println("Require: <path/to/file.pcap>");
            System.exit(-1);
        }

        Pcap pcap = new Pcap(args[0]); //call reader + writer
        System.out.println("Total Packets: " + pcap.getPhysicalBitList().size());

        PcapParser pcapParser = new PcapParser(pcap);
        pcapParser.parseGlobalHeader();
    }
}
