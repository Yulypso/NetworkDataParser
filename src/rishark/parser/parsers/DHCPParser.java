package rishark.parser.parsers;

import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.ApplicationProtocol;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dhcp.DHCPOptionsCode;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dhcp.Dhcp;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dhcp.Option;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dhcp.options.*;

public class DHCPParser {

    private final ApplicationProtocol applicationProtocol;

    public DHCPParser(ApplicationProtocol applicationProtocol) {
        this.applicationProtocol = applicationProtocol;
    }

    public void parse() {
        System.out.print("\t\tOpCode: " + ((Dhcp)this.applicationProtocol).getOpCode());
        System.out.println("\t\t\t\t\t\tTransaction ID: " + ((Dhcp)this.applicationProtocol).getTransactionId());
        System.out.print("\t\tClient MAC address: " + ((Dhcp)this.applicationProtocol).getClientMacAddress());
        System.out.println("\t\t\t\tClient IP address: " + ((Dhcp)this.applicationProtocol).getYourIpAddress());
        System.out.println("\t\tServer IP address: " + ((Dhcp)this.applicationProtocol).getServerIpAddress());

        for (Option o: ((Dhcp)this.applicationProtocol).getOptionList()) {
            switch (DHCPOptionsCode.findDhcpOptionsCode(o.getCode())){
                case ROUTER -> System.out.println("\t\tRouter IP address: " + ((Router) o.getOption()).getRouterIpAddress());
                case DNS_IP -> System.out.println("\t\tDNS IP address: " + ((DnsIp) o.getOption()).getDnsIpAddress());
                case REQUESTED_IP_ADDRESS -> System.out.println("\t\tRequested IP address: " + ((RequestedIpAddress) o.getOption()).getRequestedIpAddress());
                case IP_ADDRESS_LEASE_TIME -> System.out.println("\t\tIP address Lease time: " + ((IpAddressLeaseTime) o.getOption()).getLeaseTimeSeconds());
                case DHCP_MESSAGE_TYPE -> System.out.println("\t\tDHCP message type: " + ((DhcpMessageType) o.getOption()).getMessageType());
                case null, default -> {}
            }
        }
    }
}
