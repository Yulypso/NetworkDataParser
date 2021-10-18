package rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dns;

public enum DNSClass {

    Reserved(0),
    IN(1),
    CH(3),
    HS(4),
    None(254),
    Any(255);

    private final int dnsClass;

    DNSClass(int dnsClass) {
        this.dnsClass = dnsClass;
    }

    public static DNSClass findDnsClass(int i){
        for(DNSClass t : DNSClass.values()) {
            if(t.getDnsClass() == i) {
                return t;
            }
        }
        return null;
    }

    public int getDnsClass() {
        return dnsClass;
    }


}
