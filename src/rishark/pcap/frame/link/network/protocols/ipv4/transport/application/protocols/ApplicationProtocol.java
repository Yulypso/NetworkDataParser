package rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols;

import rishark.pcap.frame.link.network.Protocol;

public interface ApplicationProtocol {
    String getRaw();
    Protocol getOverProtocol();
}
