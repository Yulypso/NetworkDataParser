package rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dns;

public class Tmp {

    public String s;
    private final String tmpRaw;
    private final String dnsRaw;
    public int l;

    public Tmp(String tmpRaw, String dnsRaw) {
        this.s = "";
        this.l = 0;
        this.tmpRaw = tmpRaw;
        this.dnsRaw = dnsRaw;
    }

    public String getS() {
        return s;
    }

    public String getTmpRaw() {
        return tmpRaw;
    }

    public String getDnsRaw() {
        return dnsRaw;
    }

    public int getL() {
        return l;
    }
}
