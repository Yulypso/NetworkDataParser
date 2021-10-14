package rishark.pcap.frame.link.network.protocols.ipv4.transport.application;

import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.ApplicationProtocol;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.ftp.Ftp;

public class ApplicationRishar {

    private ApplicationProtocol applicationProtocol;

    private final String raw;
    private final AppProtocol appProtocol;

    public ApplicationRishar(String raw, AppProtocol protocol) {
        this.raw = raw;
        this.appProtocol = protocol;

        switch (this.getAppProtocol()) {
            case FTP -> this.applicationProtocol = new Ftp(raw);
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
}
