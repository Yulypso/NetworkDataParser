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
        char a;
        char b;

        for (int i = 0; i < nbBytes * 2; i+=2) {
            a = (raw.charAt(pos + i));
            b = (raw.charAt(pos + i+1));
            sb.append(a).append(b);
        }

        return sb.toString();
    }

    public static String hexStringToString(String s) {
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < s.length(); i += 2) {
            String str = s.substring(i, i + 2);
            sb.append((char) hexStringToInt(str));
        }
        return sb.toString();
    }

    public static long hexStringToLong(String s) {
        return Long.parseLong(s, 16);
    }

    public static int hexStringToInt(String s) {
        return Integer.parseInt(s,16);
    }

    public static String hexStringToBinary(String s) {
            return String.format("%" + s.length() * 4 + "s", Integer.toBinaryString(Utils.hexStringToInt(s))).replaceAll(" ", "0");
    }

    public static int binaryStringToInt(String s) {
        return Integer.parseInt(s,2);
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

    public static String bytesToIPv4(String bytes){
        String[] ss = bytes.replaceAll("(..)(?!$)", "$1%").split("%");
        StringBuilder sb = new StringBuilder();
        for (String s: ss) {
            sb.append(hexStringToInt(s)).append(".");
        }
        return sb.substring(0, sb.length()-1);
    }

    public static String bytesToIPv6(String bytes){
        StringBuilder sb = new StringBuilder();
        for (int i=0; i < 32; i++) {
            if (i % 4 == 0 && i != 0)
                sb.append(":");
            sb.append(bytes.charAt(i));
        }
        return sb.toString();
    }
}
