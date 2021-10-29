package rishark.debug.debuggers;

import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.ApplicationProtocol;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dhcp.DHCPOptionsCode;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dhcp.Dhcp;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dhcp.Option;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dhcp.options.*;

public class DHCPDebugger {

    private final ApplicationProtocol applicationProtocol;

    public DHCPDebugger(ApplicationProtocol applicationProtocol) {
        this.applicationProtocol = applicationProtocol;
    }

    public void parse() {
        System.out.println("OpCode: " + ((Dhcp)this.applicationProtocol).getOpCode());
        System.out.println("Hardware type: " + ((Dhcp)this.applicationProtocol).getHardwareType());
        System.out.println("Hardware address length: " + ((Dhcp)this.applicationProtocol).getAddressLength());
        System.out.println("Hops: " + ((Dhcp)this.applicationProtocol).getHops());
        System.out.println("Transaction ID: " + ((Dhcp)this.applicationProtocol).getTransactionId());
        System.out.println("Seconds elapsed: " + ((Dhcp)this.applicationProtocol).getSecondElapsed());
        System.out.println("Flags: ");
        System.out.println("\t- Broadcast: " + ((Dhcp)this.applicationProtocol).getFlagBroadcast());
        System.out.println("\t- Reserved: " + ((Dhcp)this.applicationProtocol).getFlagReserved());
        System.out.println("Client IP address: " + ((Dhcp)this.applicationProtocol).getClientIpAddress());
        System.out.println("Your IP address: " + ((Dhcp)this.applicationProtocol).getYourIpAddress());
        System.out.println("Server IP address: " + ((Dhcp)this.applicationProtocol).getServerIpAddress());
        System.out.println("Gateway IP address: " + ((Dhcp)this.applicationProtocol).getGatewayIpAddress());
        System.out.println("Client MAC address: " + ((Dhcp)this.applicationProtocol).getClientMacAddress());
        System.out.println("Client Hardware address padding: " + ((Dhcp)this.applicationProtocol).getClientHardwarePadding());
        System.out.println("Server Host name: " + ((Dhcp)this.applicationProtocol).getServerHostName());
        System.out.println("Boot file name: " + ((Dhcp)this.applicationProtocol).getBootFileName());
        System.out.println("Magic cookie: " + ((Dhcp)this.applicationProtocol).getMagicCookie());

        System.out.println("Application UDP data length: " + ((Dhcp)this.applicationProtocol).getUdpDataLength());

        for (Option o: ((Dhcp)this.applicationProtocol).getOptionList()) {
            switch (DHCPOptionsCode.findDhcpOptionsCode(o.getCode())){
                case SUBNET_MASK -> System.out.println("Subnet Mask: " + ((SubnetMask) o.getOption()).getSubnetMask());
                case ROUTER -> System.out.println("Router IP address: " + ((Router) o.getOption()).getRouterIpAddress());
                case DNS_IP -> System.out.println("DNS IP address: " + ((DnsIp) o.getOption()).getDnsIpAddress());
                case STATIC_ROUTE -> System.out.println("Static route address: " + ((StaticRoute) o.getOption()).getStaticRouteAddress());
                case REQUESTED_IP_ADDRESS -> System.out.println("Requested IP address: " + ((RequestedIpAddress) o.getOption()).getRequestedIpAddress());
                case IP_ADDRESS_LEASE_TIME -> System.out.println("IP address Lease time: " + ((IpAddressLeaseTime) o.getOption()).getLeaseTimeSeconds());
                case DHCP_MESSAGE_TYPE -> System.out.println("DHCP message type: " + ((DhcpMessageType) o.getOption()).getMessageType());
                case DHCP_SERVER_IDENTIFIER -> System.out.println("DHCP server identifier: " + ((DhcpServerIdentifier) o.getOption()).getServerIdentifierIpAddress());
                case PARAMETER_REQUEST_LIST -> System.out.println("Parameter request list: " + ((ParameterRequestList) o.getOption()).getMessageTypeList());
                case RENEWAL_TIME_VALUE -> System.out.println("Renewal time: " + ((RenewalTimeValue) o.getOption()).getRenewalTimeSeconds());
                case REBINDING_TIME_VALUE -> System.out.println("Rebinding time: " + ((RebindingTimeValue) o.getOption()).getRebindingTimeSeconds());
                case CLIENT_IDENTIFIER -> {
                    System.out.println("Client identifier: ");
                    System.out.println("\t- Hardware type: " + ((ClientIdentifier) o.getOption()).getHardwareType());
                    System.out.println("\t- Mac address " + ((ClientIdentifier) o.getOption()).getMacAddress());
                }
                case null, default -> {}
            }
        }
        if (this.applicationProtocol.getRaw().length() > 0)
            System.out.println("Application DHCP raw: " + this.applicationProtocol.getRaw());
    }
}
