package rishark.pcap.frame.link.protocols.arp;

public enum OpCode {
    Reserved(0),
    Request(1),
    Reply(2),
    Request_Reverse(3),
    Reply_Reverse(4),
    DRARP_Request(5),
    DRARP_Reply(6),
    DRARP_ERROR(7),
    InARP_Request(8),
    InARP_Reply(9),
    ARP_NAK(10),
    MARS_Request(11),
    MARS_Multi(12),
    MARS_MServ(13),
    MARS_Join(14),
    MARS_Leave(15),
    MARS_NAK(16),
    MARS_Unserv(17),
    MARS_SJoin(18),
    MARS_SLeave(19),
    MARS_Grouplist_Request(20),
    MARS_Grouplist_Reply(21),
    MARS_Redirect_Map(22),
    MAPOS_UNARP(23),
    OP_EXP1(24),
    OP_EXP2(25);

    private final int opCode;

    OpCode(int opCode) {
        this.opCode = opCode;
    }

    public static OpCode findOpCode(int i){
        for(OpCode o : OpCode.values()) {
            if(o.getOpCode() == i) {
                return o;
            }
        }
        return null;
    }

    public int getOpCode() {
        return opCode;
    }
}
