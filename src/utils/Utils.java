package utils;

import java.io.FileInputStream;
import java.io.InputStream;

public class Utils {

    public static String readPcap(String path){
        String raw = "";

        try {
            InputStream inputstream = new FileInputStream(path);
            System.out.println("File opened:" + path);

            StringBuilder sb = new StringBuilder();
            int b = inputstream.read();
            while (b != -1) {
                sb.append(String.format("%02x", b));
                b = inputstream.read();
            }
            raw = sb.toString();

        } catch (Exception e) {
            e.printStackTrace();
        }

        return raw;
    }

    public static long read4bytesFromIndex(String raw, int pos, boolean isBigEndian) {
        pos *= 2;
        String s;

        if (isBigEndian)
            s = ("" + raw.charAt(pos) + raw.charAt(pos + 1) + raw.charAt(pos + 2) + raw.charAt(pos + 3) + raw.charAt(pos + 4) + raw.charAt(pos + 5) + raw.charAt(pos + 6) + raw.charAt(pos + 7));
        else
            s = ("" + raw.charAt(pos + 6) + raw.charAt(pos + 7) + raw.charAt(pos + 4) + raw.charAt(pos + 5) + raw.charAt(pos + 2) + raw.charAt(pos + 3) + raw.charAt(pos) + raw.charAt(pos + 1));
        return Long.parseLong(s, 16);
    }

    public static int read2bytesFromIndex(String raw, int pos, boolean isBigEndian) {
        pos *= 2;
        String s;
        if (isBigEndian)
            s = ("" + raw.charAt(pos) + raw.charAt(pos + 1) + raw.charAt(pos + 2) + raw.charAt(pos + 3));
        else
            s = ("" + raw.charAt(pos + 2) + raw.charAt(pos + 3) + raw.charAt(pos) + raw.charAt(pos + 1));
        return Integer.parseInt(s,16);
    }

    public static String toHexString(long l) {
        return String.format("%08x", l);
    }

    public static String toHexString(int i) {
        return String.format("%04x", i);
    }

    public static void displayHex(Long l) {
        System.out.printf("%08x", l);
    }

    public static void displayHex(int i) {
        System.out.printf("%04x", i);
    }
}
