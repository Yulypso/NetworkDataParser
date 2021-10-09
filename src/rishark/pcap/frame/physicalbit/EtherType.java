package rishark.pcap.frame.physicalbit;

public enum EtherType {
    ARP("0806"),
    IPv4("0800"),
    IPv6("86dd");

    private final String etherType;

    EtherType(String etherType) {
        this.etherType = etherType;
    }

    public static EtherType findEtherType(String bytes){
        for(EtherType e : EtherType.values()) {
            if(e.getEtherType().equals(bytes)) {
                return e;
            }
        }
        return null;
    }

    public String getEtherType() {
        return etherType;
    }
}
