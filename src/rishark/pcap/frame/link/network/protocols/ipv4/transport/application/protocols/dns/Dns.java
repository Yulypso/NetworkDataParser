package rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dns;

import rishark.pcap.frame.link.network.Protocol;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.ApplicationProtocol;

public class Dns implements ApplicationProtocol {

    private final String raw;
    private final Protocol overProtocol;

    public Dns(String raw, Protocol overProtocol) {
        this.raw = raw;
        this.overProtocol = overProtocol;
    }

    public String getRaw() {
        return raw;
    }

    public Protocol getOverProtocol() {
        return overProtocol;
    }
}
