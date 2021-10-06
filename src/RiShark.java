import rishark.Pcap;
import utils.PcapReader;

public class RiShark {

    public static void main(String[] args) {

        if (args.length != 1) {
            System.out.println("Require: <path/to/file.pcap>");
            System.exit(-1);
        }


        Pcap pcap = new Pcap(args[0]); //call reader + writer
    }
}
