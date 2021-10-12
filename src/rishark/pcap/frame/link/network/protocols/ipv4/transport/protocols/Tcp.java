package rishark.pcap.frame.link.network.protocols.ipv4.transport.protocols;

public class Tcp implements TransportProtocol{

    private final String raw;

    public Tcp(String raw) {

        this.raw = raw; // TODO: edit value later
    }

    @Override
    public String getRaw() {
        return this.raw;
    }
}
