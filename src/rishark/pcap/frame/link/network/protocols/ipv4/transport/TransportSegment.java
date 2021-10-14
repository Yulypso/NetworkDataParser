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

import javax.lang.model.type.NullType;
import java.util.Objects;

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

                // TODO: methods determine app protocol
                // TODO: use switch for app protocol
                if (this.getRaw().length() > 0)
                {
                    determineProtocol();
                    if(this.appProtocol != null)
                        this.applicationRishar = new ApplicationRishar(this.getRaw(), this.appProtocol);
                }
            }
            case UDP -> {
                this.transportProtocolBase = new Udp(raw);
                this.raw = this.transportProtocolBase.getRaw();
            }
        }
    }

    private void determineProtocol(){
        int port = this.transportProtocolBase.getAppPort();

        switch (port){
            case 21: case 22: {
                if(FTPCommand.findFtpCommand(Utils.hexStringToString(Utils.readBytesFromIndex(this.getRaw(),0,4)).trim()) != null ||
                        FTPCode.findFtpCode(Utils.hexStringToString(Utils.readBytesFromIndex(this.getRaw(),0,4)).trim()) != null) {
                    this.appProtocol = AppProtocol.findProtocol("ftp");
                }
                break;
            }
            default: {
                this.appProtocol = null;
                break;
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

    public long getTransportSegmentSize() {
        return this.transportProtocolBase.getRaw().length() + this.getRaw().length();
    }

    public AppProtocol getAppProtocol() {
        return appProtocol;
    }
}
