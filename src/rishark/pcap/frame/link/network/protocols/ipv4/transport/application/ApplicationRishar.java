package rishark.pcap.frame.link.network.protocols.ipv4.transport.application;

import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.ApplicationProtocol;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.Ftp;

public class ApplicationRishar {

    private ApplicationProtocol applicationProtocol;

    private final String raw;
    private final String appProtocol;

    public ApplicationRishar(String raw, AppProtocol protocol){
        //TODO: such as NetworkPacket, get protocol type and create protocol
        this.applicationProtocol = new Ftp(raw);

        this.raw = raw;
        this.appProtocol = protocol.getProtocol();
    }

    public String getRaw() {
        return raw;
    }

    public String getAppProtocol() {
        return appProtocol;
    }

    public ApplicationProtocol getApplicationProtocol() {
        return applicationProtocol;
    }
}
