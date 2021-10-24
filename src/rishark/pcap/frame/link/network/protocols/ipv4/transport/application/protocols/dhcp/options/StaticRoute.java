package rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dhcp.options;

import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dhcp.Option;
import utils.Utils;

public class StaticRoute implements OptionInterface {

    private final String staticRouteAddress;

    public StaticRoute(String data, int length) {
        this.staticRouteAddress = Utils.bytesToIPv4(Utils.readBytesFromIndex(data, 0, length));
    }

    public String getStaticRouteAddress() {
        return staticRouteAddress;
    }
}
