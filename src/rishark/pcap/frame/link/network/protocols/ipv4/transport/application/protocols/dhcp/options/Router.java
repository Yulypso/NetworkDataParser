package rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dhcp.options;

import utils.Utils;

public class Router implements OptionInterface {

    private final String routerIpAddress;

    public Router(String data, int length) {
        this.routerIpAddress = Utils.bytesToIPv4(Utils.readBytesFromIndex(data, 0, length));
    }

    public String getRouterIpAddress() {
        return routerIpAddress;
    }
}
