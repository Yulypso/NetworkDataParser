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

    public static String readBytesFromIndex(String raw, int pos, int nbBytes, boolean isBigEndian){
        pos *= 2;
        StringBuilder sb = new StringBuilder();

        if (isBigEndian){
            for (int i = 0; i < nbBytes * 2; i+=2) {
                sb.append(raw.charAt(pos + i)).append(raw.charAt(pos + i+1));
            }
        } else {
            for (int i = nbBytes * 2 - 1; i >= 0; i-=2) {
                sb.append(raw.charAt(pos + i - 1)).append(raw.charAt(pos + i));
            }
        }
        return sb.toString();
    }

    public static String readBytesFromIndex(String raw, int pos, int nbBytes){
        pos *= 2;
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < nbBytes * 2; i+=2) {
            sb.append(raw.charAt(pos + i)).append(raw.charAt(pos + i+1));
        }

        return sb.toString();
    }

    public static long hexStringToLong(String s) {
        return Long.parseLong(s, 16);
    }

    public static int hexStringToInt(String s) {
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

    public static String bytesToIP(String bytes){
        String[] ss = bytes.replaceAll("(..)(?!$)", "$1%").split("%");
        StringBuilder sb = new StringBuilder();
        for (String s: ss) {
            sb.append(hexStringToInt(s)).append(".");
        }
        return sb.substring(0, sb.length()-1);
    }
}
