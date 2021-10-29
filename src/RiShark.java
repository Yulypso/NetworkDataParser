import rishark.debug.PcapDebugger;
import rishark.parser.PcapParser;
import rishark.pcap.Pcap;
import rishark.pcap.frame.PacketHeader;
import utils.Utils;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class RiShark {

    public static void main(String[] args) {

        String inputFileName = null;
        boolean debug = false;
        boolean fragIp = false;
        boolean tcpStream = false;
        List<String> numberList = new LinkedList<>();

        if (args.length < 1) {
            System.out.println("[Error]: Not enough arguments");
            System.exit(-1);
        } else {
            for (int i = 0; i < args.length; i++) {
                switch (args[i]) {
                    case "-i", "--input" -> inputFileName = args[i + 1];
                    case "-n", "--number" -> {
                        boolean isNumber = true;
                        int nb = 0;
                        ++i;
                        while (isNumber && i < args.length) {
                            try {
                                nb = Integer.parseInt(args[i]);
                                System.out.println(nb);
                                numberList.add(String.valueOf(nb));
                                ++i;
                            } catch (Exception e) {
                                --i;
                                isNumber = false;
                            }
                        }
                    }
                    case "-d", "--debug" -> debug = true;
                    case "-f", "--frag-ip" -> fragIp = true;
                    case "-t", "--tcp-stream" -> tcpStream = true;
                    case "-h", "--help" -> Utils.displayHelp();
                }
            }

            if (inputFileName != null){
                Pcap pcap = new Pcap(inputFileName);

                String[] numbersArray = new String[numberList.size()];
                numbersArray = numberList.toArray(numbersArray);

                if (!debug) {
                    PcapParser pcapParser = new PcapParser(pcap);

                    pcapParser.parseGlobalHeader();
                    pcapParser.parseFrame(Arrays.stream(numbersArray)
                            .toList()
                            .stream()
                            .mapToInt(Integer::parseInt)
                            .toArray());
                } else {
                    PcapDebugger pcapDebugger = new PcapDebugger(pcap);

                    pcapDebugger.numberOfFrames();
                    pcapDebugger.parseGlobalHeader();
                    pcapDebugger.parseFrame(Arrays.stream(numbersArray)
                            .toList()
                            .stream()
                            .mapToInt(Integer::parseInt)
                            .toArray());
                }
            } else {
                System.out.println("[Error]: No input file");
                System.exit(-1);
            }
        }
    }
}
