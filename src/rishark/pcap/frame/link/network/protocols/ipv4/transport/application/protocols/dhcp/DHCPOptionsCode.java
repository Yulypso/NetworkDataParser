package rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dhcp;

public enum DHCPOptionsCode {

    SUBNET_MASK(1), // o a
    TIME_OFFSET(2),
    ROUTER(3),
    TIME_SERVER(4),
    NAME_SERVER(5),
    DNS_IP(6),
    LOG_SERVER(7),
    QUOTE_SERVER(8),
    LPR_SERVER(9),
    IMPRESS_SERVER(10),
    RESOURCE_LOCATION_SERVER(11),
    HOST_NAME(12),
    BOOT_FILE_SIZE(13),
    MERIT_DUMP_FILE(14),
    DOMAIN_NAME(15),
    SWAP_SERVER(16),
    ROOT_PATH(17),
    EXTENSIONS_PATH(18),
    IP_FORWARDING_ENABLE_DISABLE(19),
    NON_LOCAL_SOURCE_ROUTING_ENABLE_DISABLE(20),
    POLICY_FILTER(21),
    MAXIMUM_DATAGRAM_REASSEMBLY_SIZE(22),
    DEFAULT_IP_TTL(23),
    PATH_MTU_AGING_TIMEOUT(24),
    PATH_MTU_PLATEAU_TABLE(25),
    MTU_INTERFACE(26),
    ALL_SUBNETS_LOCAL(27),
    BROADCAST_ADDRESS(28),
    PERFORM_MASK_DISCOVERY(29),
    MASK_SUPPLIER(30),
    PERFORM_ROUTER_DISCOVERY(31),
    ROUTER_SOLICITATION_ADDRESS(32),
    STATIC_ROUTE(33),
    NTP_SERVER(42),
    NETBIOS_NS(44),
    NETBIOS_SCOPE(47),
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
    DOMAIN_SEARCH(119),
    CLASSLESS_STATIC_ROUTE(121),
    TFTP_SERVER_ADDRESS(150),
    PRIVATE_STATIC_ROUTE(249),
    PRIVATE_AUTODISCOVERY(252),
    END(255); // d o r a

    // TODO implementer les autres code

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
