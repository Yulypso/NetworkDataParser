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
        System.out.print("\t\t\t\t\t\tHops: " + ((Dhcp)this.applicationProtocol).getHops());
        System.out.println("\t\t\t\t\t\t\t\t\tTransaction ID: " + ((Dhcp)this.applicationProtocol).getTransactionId());
        System.out.print("\t\tClient MAC address: " + ((Dhcp)this.applicationProtocol).getClientMacAddress());
        System.out.println("\tClient IP address: " + ((Dhcp)this.applicationProtocol).getYourIpAddress());
        System.out.print("\t\tGateway IP address: " + ((Dhcp)this.applicationProtocol).getGatewayIpAddress());
        System.out.println("\t\t\t\tServer IP address: " + ((Dhcp)this.applicationProtocol).getServerIpAddress());

        for (Option o: ((Dhcp)this.applicationProtocol).getOptionList()) {
            switch (DHCPOptionsCode.findDhcpOptionsCode(o.getCode())){
                case SUBNET_MASK -> System.out.println("\t\tSubnet Mask: " + ((SubnetMask) o.getOption()).getSubnetMask());
                case ROUTER -> System.out.println("\t\tRouter IP address: " + ((Router) o.getOption()).getRouterIpAddress());
                case DNS_IP -> System.out.println("\t\tDNS IP address: " + ((DnsIp) o.getOption()).getDnsIpAddress());
                case STATIC_ROUTE -> System.out.println("\t\tStatic route address: " + ((StaticRoute) o.getOption()).getStaticRouteAddress());
                case REQUESTED_IP_ADDRESS -> System.out.println("\t\tRequested IP address: " + ((RequestedIpAddress) o.getOption()).getRequestedIpAddress());
                case IP_ADDRESS_LEASE_TIME -> System.out.println("\t\tIP address Lease time: " + ((IpAddressLeaseTime) o.getOption()).getLeaseTimeSeconds());
                case DHCP_MESSAGE_TYPE -> System.out.println("\t\tDHCP message type: " + ((DhcpMessageType) o.getOption()).getMessageType());
                case DHCP_SERVER_IDENTIFIER -> System.out.println("\t\tDHCP server identifier: " + ((DhcpServerIdentifier) o.getOption()).getServerIdentifierIpAddress());
                case PARAMETER_REQUEST_LIST -> System.out.println("\t\tParameter request list: " + ((ParameterRequestList) o.getOption()).getMessageTypeList());
                case RENEWAL_TIME_VALUE -> System.out.println("\t\tRenewal time: " + ((RenewalTimeValue) o.getOption()).getRenewalTimeSeconds());
                case REBINDING_TIME_VALUE -> System.out.println("\t\tRebinding time: " + ((RebindingTimeValue) o.getOption()).getRebindingTimeSeconds());
                case CLIENT_IDENTIFIER -> {
                    System.out.println("\t\tClient identifier: ");
                    System.out.println("\t\t\t- Hardware type: " + ((ClientIdentifier) o.getOption()).getHardwareType());
                    System.out.println("\t\t\t- Mac address " + ((ClientIdentifier) o.getOption()).getMacAddress());
                }
                case null, default -> {}
            }
        }
    }
}
