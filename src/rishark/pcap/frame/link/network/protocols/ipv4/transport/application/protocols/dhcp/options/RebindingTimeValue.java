package rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dhcp.options;

import utils.Utils;

public class RebindingTimeValue {

    private final int rebindingTimeSeconds; // seconds

    public RebindingTimeValue(String data, int length) {
        this.rebindingTimeSeconds = Utils.hexStringToInt(Utils.readBytesFromIndex(data, 0, length));
    }

    public int getRebindingTimeSeconds() {
        return rebindingTimeSeconds;
    }
}

