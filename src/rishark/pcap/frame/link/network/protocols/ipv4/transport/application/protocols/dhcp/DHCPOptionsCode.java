package rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dhcp;

public enum DHCPOptionsCode {

    SUBNET_MASK(1), // o a
    ROUTER(3),
    DNS_IP(6),
    STATIC_ROUTE(33),
    REQUESTED_IP_ADDRESS(50), // d r
    IP_ADDRESS_LEASE_TIME(51), // o a
    DHCP_MESSAGE_TYPE(53), // d o r a
    DHCP_SERVER_IDENTIFIER(54), // o r a
    PARAMETER_REQUEST_LIST(55), // d r
    RENEWAL_TIME_VALUE(58), // o a
    REBINDING_TIME_VALUE(59), // o a
    VENDOR_CLASS_IDENTIFIER(60),
    CLIENT_IDENTIFIER(61), // d r
    TFTP_SERVER_NAME(66),
    BOOT_FILE_NAME(67),
    CLASSLESS_STATIC_ROUTE(121),
    TFTP_SERVER_ADDRESS(150),
    END(255); // d o r a

    private final int dhcpOptionsCode;

    DHCPOptionsCode(int dhcpOptionsCode) {
        this.dhcpOptionsCode = dhcpOptionsCode;
    }

    public static DHCPOptionsCode findDhcpOptionsCode(int i){
        for(DHCPOptionsCode oc : DHCPOptionsCode.values()) {
            if(oc.getDhcpOptionsCode() == i) {
                return oc;
            }
        }
        return null;
    }

    public int getDhcpOptionsCode() {
        return dhcpOptionsCode;
    }
}
