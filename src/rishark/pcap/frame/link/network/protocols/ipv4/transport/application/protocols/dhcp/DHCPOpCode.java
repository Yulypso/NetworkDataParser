package rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dhcp;

public enum DHCPOpCode {

    BOOTREQUEST(1),
    BOOTREPLY(2);

    private final int dhcpOpCode;

    DHCPOpCode(int dhcpOpCode) {
        this.dhcpOpCode = dhcpOpCode;
    }

    public static DHCPOpCode findDhcpOpCode(int i){
        for(DHCPOpCode oc : DHCPOpCode.values()) {
            if(oc.getDhcpOpCode() == i) {
                return oc;
            }
        }
        return null;
    }

    public int getDhcpOpCode() {
        return dhcpOpCode;
    }
}
