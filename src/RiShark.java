import java.io.FileReader;
import java.util.Locale;

public class RiShark {

    public static void main(String[] args) {

        if (args.length != 1) {
            System.out.println("Require: <filename>.pcap");
            System.exit(-1);
        }

        if (System.getProperty("os.name").toLowerCase().contains("windows")) {
            System.out.println(System.getProperty("user.dir") + "\\" + args[0]);
        } else {
            System.out.println(System.getProperty("user.dir") + "/" + args[0]);
        }

        /*try {
            FileReader fileReader = new FileReader(args[0]);

            int r = 0;
            while((r = fileReader.read()) != -1) {
                System.out.print((char) r);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }*/
    }
}
