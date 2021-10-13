package rishark.pcap.frame.link.network.protocols.ipv4.transport;

import rishark.pcap.frame.link.network.Protocol;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.AppProtocol;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.ApplicationRishar;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.protocols.Tcp;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.protocols.TransportProtocol;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.protocols.Udp;

public class TransportSegment {

    private ApplicationRishar applicationRishar;

    /* Base */
    private TransportProtocol transportProtocolBase; // TCP, UDP

    private String raw;

    public TransportSegment (String raw, Protocol ipProtocol) {
        switch (ipProtocol) {
            case TCP -> {
                this.transportProtocolBase = new Tcp(raw);
                this.raw = this.transportProtocolBase.getRaw();

                // TODO: methods determine app protocol
                // TODO: use switch for app protocol
                if (this.getRaw().length() > 0)
                    this.applicationRishar = new ApplicationRishar(this.getRaw(), AppProtocol.FTP);
            }
            case UDP -> {
                this.transportProtocolBase = new Udp(raw);
                this.raw = this.transportProtocolBase.getRaw();
            }
        }
    }

    public TransportProtocol getTransportProtocolBase() {
        return transportProtocolBase;
    }

    public ApplicationRishar getApplicationRishar() {
        return applicationRishar;
    }

    public String getRaw() {
        return raw;
    }
}
