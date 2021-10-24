package rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dhcp.options;

import utils.Utils;

public class StaticRoute {

    private final String staticRouteAddress;

    public StaticRoute(String data, int length) {
        this.staticRouteAddress = Utils.bytesToIPv4(Utils.readBytesFromIndex(data, 0, length));
    }

    public String getStaticRouteAddress() {
        return staticRouteAddress;
    }
}
