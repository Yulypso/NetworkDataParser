import rishark.parser.PcapParser;
import rishark.pcap.Pcap;

import java.util.Arrays;
import java.util.stream.Stream;

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


        pcapParser.parseFrame(Arrays.stream(args)
                  .toList()
                  .subList(1, args.length)
                  .stream()
                  .mapToInt(Integer::parseInt)
                  .toArray());

        // "C:\Users\Thierry KHAMPHOUSONE\IdeaProjects\RiShark\rishark.pcap" 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63 64 65 66 67 68 69 70 71 72 73 74 75 76 77 78 79 80 81 82 83 84 85 86 87 88 89 90 91 92 93 94 95 96 97 98 99 100
    }
}
