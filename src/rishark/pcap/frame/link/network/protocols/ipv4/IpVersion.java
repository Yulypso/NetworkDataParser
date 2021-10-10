package rishark.pcap.frame.link.network.protocols.ipv4;

public enum IpVersion {

    Reserved(0),
    Unassigned(1),
    Unassigned2(2),
    Unassigned3(3),
    Ip_Version_4(4),
    Stream_Ip_Datagram_mode(5),
    Ip_Version_6(6),
    TP_IX(7),
    P_IP(8),
    TUBA(9),
    Unassigned4(10),
    Unassigned5(11),
    Unassigned6(12),
    Unassigned7(13),
    Unassigned8(14),
    Reserved2(15);


    private final int ipVersion;

    IpVersion(int ipVersion) {
        this.ipVersion = ipVersion;
    }

    public static IpVersion findIpVersion(int i){
        for(IpVersion ip : IpVersion.values()) {
            if(ip.getIpVersion() == i) {
                return ip;
            }
        }
        return null;
    }

    public int getIpVersion() {
        return ipVersion;
    }
}
