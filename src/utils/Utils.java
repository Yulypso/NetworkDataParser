package utils;

import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dns.Tmp;

import java.io.FileInputStream;
import java.io.InputStream;
import java.util.regex.Pattern;

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

    public static String bytesToMAC(String bytes){
        return bytes.replaceAll("(..)(?!$)", "$1:");
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

    public static String readDataNameFromTmpRaw(String tmpRaw){
        String data = null;
        int nbChar = Utils.hexStringToInt(Utils.readBytesFromIndex(tmpRaw, 0, 1));
        tmpRaw = Utils.readBytesFromIndex(tmpRaw, 1, (tmpRaw.length() / 2) - 1);

        StringBuilder qn = new StringBuilder();
        while (nbChar != 0) {
            for (int i = 0; i < nbChar; i++) {
                qn.append(Utils.hexStringToString(Utils.readBytesFromIndex(tmpRaw, i, 1)));
            }
            qn.append(".");
            tmpRaw = Utils.readBytesFromIndex(tmpRaw, nbChar, (tmpRaw.length() / 2) - nbChar);
            if (("" + Utils.hexStringToBinary(Utils.readBytesFromIndex(tmpRaw, 0, 1)).charAt(0) + Utils.hexStringToBinary(Utils.readBytesFromIndex(tmpRaw, 0, 1)).charAt(1)).equals("11")) { // pointer detected
                nbChar = 0;
                qn.append(Utils.readBytesFromIndex(tmpRaw, 0, 2)); // append pointer + pointer value
                tmpRaw = Utils.readBytesFromIndex(tmpRaw, 2, (tmpRaw.length() / 2) - 2); // save pointer value
                data = qn.toString();
            } else {
                nbChar = Utils.hexStringToInt(Utils.readBytesFromIndex(tmpRaw, 0, 1));
                tmpRaw = Utils.readBytesFromIndex(tmpRaw, 1, (tmpRaw.length() / 2) - 1);
                data = qn.substring(0, qn.length() - 1);
            }
        }
        return data;
    }

    public static boolean verifyPointerInName(String name) {
        Pattern p = Pattern.compile("^([c])([0-9a-f]){3}");

        String[] ss = name.split("\\.");
        for (String s: ss) {
            if (p.matcher(s).matches())
                    return true;
        }
        return false;
    }

    public static String readNamePointer(String dnsRaw, String name) {
        Pattern p = Pattern.compile("^([c])([0-9a-f]){3}");
        String[] ss = name.split("\\.");
        int pointerValue = 0;
        int i = 0;
        for (String s: ss) {
            if (p.matcher(s).matches()) {
                pointerValue = Utils.binaryStringToInt(Utils.hexStringToBinary(s).substring(2, 16)) * 2;
                break;
            }
            i++;
        }
        if (pointerValue != 0){
            String a = Utils.readDataNameFromTmpRaw(dnsRaw.substring(pointerValue));
            StringBuilder sb = new StringBuilder();
            for (int j = 0; j < i; j++) {
                sb.append(ss[j]).append(".");
            }
            return sb + a;
        } else
            return name;
    }

    public static Tmp retrievesTmp(Tmp tmp) {
        String tmpRaw = tmp.getTmpRaw();
        String dnsRaw = tmp.getDnsRaw();

        String st = Utils.hexStringToBinary(Utils.readBytesFromIndex(tmpRaw, 0, 2));
        if (st.startsWith("11")) {
            tmp.s = Utils.readNamePointer(dnsRaw, tmpRaw);
            tmp.l += 2;

            while (Utils.verifyPointerInName(tmp.s)) {
                tmp.s = Utils.readNamePointer(dnsRaw, tmp.s);
                tmp.l += 2;
            }
        } else {
            tmp.s = Utils.readDataNameFromTmpRaw(tmpRaw);
            if(Utils.verifyPointerInName(tmp.s))
                tmp.l = tmp.s.length() - 2; // remove pointer (4 char)
            else
                tmp.l = tmp.s.length() + 2; //null byte
            while (Utils.verifyPointerInName(tmp.s)) {
                tmp.s = Utils.readNamePointer(dnsRaw, tmp.s);
            }
        }
        return tmp;
    }

    public static void displayHelp() {}
}
