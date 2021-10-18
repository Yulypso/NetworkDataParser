package rishark.pcap.frame.link.network.protocols.ipv4.transport.application;

import rishark.pcap.frame.link.network.Protocol;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.ApplicationProtocol;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dns.Dns;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.ftp.Ftp;

public class ApplicationRishar {

    private ApplicationProtocol applicationProtocol;

    private final String raw;
    private final AppProtocol appProtocol;
    private final Protocol overProtocol;

    public ApplicationRishar(String raw, AppProtocol protocol, Protocol overProtocol, long udpDataLength) {
        this.raw = raw;
        this.appProtocol = protocol;
        this.overProtocol = overProtocol;

        switch (this.getAppProtocol()) {
            case FTP -> this.applicationProtocol = new Ftp(this.raw, this.overProtocol);
            case DNS -> this.applicationProtocol = new Dns(this.raw, this.overProtocol, udpDataLength);
        }
    }

    public String getRaw() {
        return raw;
    }

    public AppProtocol getAppProtocol() {
        return appProtocol;
    }

    public ApplicationProtocol getApplicationProtocol() {
        return applicationProtocol;
    }

    public Protocol getOverProtocol() {
        return overProtocol;
    }
}
