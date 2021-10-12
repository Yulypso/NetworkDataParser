package rishark.pcap.frame.link.network.protocols;

public interface NetworkProtocol {

    long getSize();
    int getIpProtocol();
    String getRaw();
}
