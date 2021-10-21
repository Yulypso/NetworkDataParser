package rishark.pcap.frame.link.network.protocols.ipv4.transport;

import rishark.pcap.frame.link.network.Protocol;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.AppProtocol;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.ApplicationRishar;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.ftp.FTPCode;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.ftp.FTPCommand;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.protocols.Tcp;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.protocols.TransportProtocol;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.protocols.Udp;
import utils.Utils;

public class TransportSegment {

    private ApplicationRishar applicationRishar;
    private AppProtocol appProtocol;

    /* Base */
    private TransportProtocol transportProtocolBase; // TCP, UDP

    private String raw;

    public TransportSegment (String raw, Protocol ipProtocol) {
        switch (ipProtocol) {
            case TCP -> {
                this.transportProtocolBase = new Tcp(raw);
                this.raw = this.transportProtocolBase.getRaw();

                if (this.getRaw().length() > 0)
                {
                    determineProtocol();
                    if(this.appProtocol != null)
                        this.applicationRishar = new ApplicationRishar(this.getRaw(), this.appProtocol, Protocol.TCP, 0);
                }
            }
            case UDP -> {
                this.transportProtocolBase = new Udp(raw);
                this.raw = this.transportProtocolBase.getRaw();

                if (this.getRaw().length() > 0)
                {
                    determineProtocol();
                    if(this.appProtocol != null)
                        this.applicationRishar = new ApplicationRishar(this.getRaw(), this.appProtocol, Protocol.UDP, (((Udp) this.getTransportProtocolBase()).getLength() - 8));
                }
            }
        }
    }

    private void determineProtocol(){
        int port = this.transportProtocolBase.getAppPort();

        switch (port) {
            case 21, 22 -> {
                if (FTPCommand.findFtpCommand(Utils.hexStringToString(Utils.readBytesFromIndex(this.getRaw(), 0, 4)).trim()) != null ||
                        FTPCode.findFtpCode(Utils.hexStringToString(Utils.readBytesFromIndex(this.getRaw(), 0, 4)).trim()) != null) {
                    this.appProtocol = AppProtocol.findProtocol("ftp");
                }
            }
            case 53 -> this.appProtocol = AppProtocol.findProtocol("dns");
            case 67, 68 -> this.appProtocol = AppProtocol.findProtocol("dhcp");
            default -> this.appProtocol = null;
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

    public long getTransportSegmentSize() {
        return this.transportProtocolBase.getRaw().length() + this.getRaw().length();
    }

    public AppProtocol getAppProtocol() {
        return appProtocol;
    }
}
