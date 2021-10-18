package rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.ftp;

import rishark.pcap.frame.link.network.Protocol;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.ApplicationProtocol;

public class Ftp implements ApplicationProtocol {

    private final String raw;
    private final Protocol overProtocol;

    public Ftp(String raw, Protocol overProtocol) {
        this.raw = raw;
        this.overProtocol = overProtocol;
    }

    @Override
    public String getRaw() {
        return raw;
    }

    @Override
    public Protocol getOverProtocol() {
        return this.overProtocol;
    }


}
