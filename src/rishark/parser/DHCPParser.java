package rishark.parser;

import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.ApplicationProtocol;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dhcp.Dhcp;

public class DHCPParser {

    private final ApplicationProtocol applicationProtocol;

    public DHCPParser(ApplicationProtocol applicationProtocol) {
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

        if (this.applicationProtocol.getRaw().length() > 0)
            System.out.println("Application DHCP raw: " + this.applicationProtocol.getRaw());
    }
}
