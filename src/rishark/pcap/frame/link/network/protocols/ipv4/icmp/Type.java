package rishark.pcap.frame.link.network.protocols.ipv4.icmp;

public enum Type {

    Echo_Reply(0),
    Unassigned1(1),
    Unassigned2(2),
    Destination_Unreachable(3),
    Source_Quench(4),
    Redirect(5),
    Alternate_Host_Address(6),
    Unassigned3(7),
    Echo(8),
    Router_Advertisement(9),
    Router_Selection(10),
    Time_Exceeded(11),
    Parameter_Problem(12),
    Timestamp(13),
    Timestamp_Reply(14),
    Information_Request(15),
    Information_Reply(16),
    Address_Mask_Request(17),
    Address_Mask_Reply(18),
    Reserved1(19),
    Reserved2(20),
    Traceroute(30),
    Datagram_Conversion_Error(31),
    Mobile_Host_Redirect(32),
    IPv6_Where_Are_You(33),
    IPv6_I_Am_Here(34),
    Mobile_Registration_Request(35),
    Mobile_Registration_Reply(36),
    Domain_Name_Request(37),
    Domain_Name_Reply(38),
    SKIP(39),
    Photuris(40),
    ICMP(41),
    Extended_Echo_Request(42),
    Extended_Echo_Reply(43),
    RFC3692_Exp1(253),
    RFC3692_Exp2(254),
    Reserved3(255);

    private final int type;

    Type(int type) {
        this.type = type;
    }

    public static Type findType(int i){
        for(Type t : Type.values()) {
            if(t.getType() == i) {
                return t;
            }
        }
        return null;
    }

    public int getType() {
        return type;
    }
}
