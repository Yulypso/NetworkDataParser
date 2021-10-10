package rishark.pcap.frame.link.network.protocols;

public interface NetworkProtocol {

    int getIpProtocol();
    String getRaw();
}
