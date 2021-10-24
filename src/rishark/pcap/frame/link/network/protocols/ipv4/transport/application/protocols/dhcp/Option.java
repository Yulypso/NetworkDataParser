package rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dhcp;

import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dhcp.options.*;
import utils.Utils;

import java.util.Objects;

public class Option {

    private final int code;
    private int length;
    private String data;

    private final String raw;

    public Option(String currRaw) {
        this.code = Utils.hexStringToInt(Utils.readBytesFromIndex(currRaw, 0, 1));
        if (DHCPOptionsCode.findDhcpOptionsCode(this.code) != DHCPOptionsCode.END) {
            this.length = Utils.hexStringToInt(Utils.readBytesFromIndex(currRaw, 1, 1));
            this.data = Utils.readBytesFromIndex(currRaw, 2, this.length);
            this.raw = Utils.readBytesFromIndex(currRaw, 2 + this.getLength(), (currRaw.length() / 2) - (2 + this.getLength()));

            switch (DHCPOptionsCode.findDhcpOptionsCode(this.code)){
                case SUBNET_MASK -> new SubnetMask(this.data, this.length);
                case ROUTER -> new Router(this.data, this.length);
                case DNS_IP -> new DnsIp(this.data, this.length);
                case STATIC_ROUTE -> new StaticRoute(this.data, this.length);
                case REQUESTED_IP_ADDRESS -> new RequestedIpAddress(this.data, this.length);
                case IP_ADDRESS_LEASE_TIME -> new IpAddressLeaseTime(this.data, this.length);
                case DHCP_MESSAGE_TYPE -> new DhcpMessageType(this.data, this.length);
                case DHCP_SERVER_IDENTIFIER -> new DhcpServerIdentifier(this.data, this.length);
                case PARAMETER_REQUEST_LIST -> new ParameterRequestList(this.data, this.length);
                case RENEWAL_TIME_VALUE -> new RenewalTimeValue(this.data, this.length);
                case REBINDING_TIME_VALUE -> new RebindingTimeValue(this.data, this.length);
                case CLIENT_IDENTIFIER -> new ClientIdentifier(this.data, this.length);
                case null, default -> {}
            }
        } else {
            this.raw = Utils.readBytesFromIndex(currRaw, 1, (currRaw.length() / 2) - 1);
        }
    }

    public int getCode() {
        return code;
    }

    public int getLength() {
        return length;
    }

    public String getData() {
        return data;
    }

    public String getRaw() {
        return raw;
    }
}
