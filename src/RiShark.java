import rishark.parser.PcapParser;
import rishark.pcap.Pcap;

public class RiShark {

    public static void main(String[] args) {

        if (args.length < 1) {
            System.out.println("Require: <path/to/file.pcap> [frame n°]");
            System.exit(-1);
        }

        Pcap pcap = new Pcap(args[0]); //call reader + writer
        System.out.println("Total Packets: " + pcap.getFrameList().size());

        PcapParser pcapParser = new PcapParser(pcap);

        pcapParser.numberOfFrames();
        pcapParser.parseGlobalHeader();

        try {
            pcapParser.parseFrame(Integer.parseInt(args[1]));
        } catch (Exception e) {
            pcapParser.parseFrame();
        }

    }
}
