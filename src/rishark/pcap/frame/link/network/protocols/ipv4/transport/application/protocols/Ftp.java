package rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols;

public class Ftp implements ApplicationProtocol{

    private final String raw;

    public Ftp(String raw) {
        this.raw = raw;
    }

    @Override
    public String getRaw() {
        return raw;
    }
}
