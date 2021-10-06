package utils;

import java.io.FileInputStream;
import java.io.InputStream;

public class PcapReader {

    private String raw;

    public PcapReader(String path){
        try {
            InputStream inputstream = new FileInputStream(path);
            System.out.println("File opened:" + path);

            StringBuilder sb = new StringBuilder();
            int b = inputstream.read();
            while (b != -1) {
                sb.append(Integer.toHexString(b));
                b = inputstream.read();
            }
            this.raw = sb.toString();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String getRaw() {
        return raw;
    }

    public void setRaw(String raw) {
        this.raw = raw;
    }
}
