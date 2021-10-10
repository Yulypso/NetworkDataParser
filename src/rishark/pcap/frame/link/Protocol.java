package rishark.pcap.frame.link;

public enum Protocol {
    ARP("0806"),
    IPv4("0800"),
    IPv6("86dd"),
    DEC_1("6000"),
    DEC_2("0609"),
    XNS("0600"),
    Domain("8019"),
    RARP("8035"),
    E802_1Q("8100"),
    AppleTalk("809b");

    private final String etherType;

    Protocol(String etherType) {
        this.etherType = etherType;
    }

    public static Protocol findEtherType(String bytes){
        for(Protocol e : Protocol.values()) {
            if(e.getProtocol().equals(bytes)) {
                return e;
            }
        }
        return null;
    }

    public String getProtocol() {
        return etherType;
    }
}