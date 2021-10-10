package rishark.pcap.frame.link.protocols.arp;

public enum HardwareType {

    Reserved(0),
    Ethernet(1),
    Experimental_Ethernet(2),
    Amateur_Radio_AX35(3),
    Proteon_ProNET_Token_Ring(4),
    Chaos(5),
    IEEE_802(6),
    ARCNET(7),
    Hyperchannel(8),
    Lanstar(9),
    Autonet_Short_Address(10),
    LocalTalk(11),
    LocalNet(12),
    Ultra_link(13),
    SMDS(14),
    Frame_Relay(15),
    ATM(16),
    HDLC(17),
    Fibre_Channel(18),
    ATM2(19),
    Serial_Line(20),
    ATM3(21),
    MIL_STD_188_220(22),
    Metricom(23),
    IEE_1394_1995(24),
    MAPOS(25),
    Twinaxial(26),
    EUI_64(27),
    HIPARP(28),
    IP_ARP_over_ISP_7816_3(29),
    ARPSec(30),
    IPsec_tunnel(31),
    Infiniband(32),
    CAI(33),
    Wiegand_Interface(34),
    Pure_IP(35),
    HW_EXP1(36),
    HW_EXP2(256),
    Reserved2(65535);


    private final int hardwareType;

    HardwareType(int opCode) {
        this.hardwareType = opCode;
    }

    public static HardwareType findHardwareType(int i){
        for(HardwareType h : HardwareType.values()) {
            if(h.getHardwareType() == i) {
                return h;
            }
        }
        return null;
    }

    public int getHardwareType() {
        return hardwareType;
    }
}
