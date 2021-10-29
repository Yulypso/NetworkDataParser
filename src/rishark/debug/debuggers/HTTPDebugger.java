package rishark.debug.debuggers;

import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.ApplicationProtocol;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.http.Http;

public class HTTPDebugger {

    private final ApplicationProtocol applicationProtocol;

    public HTTPDebugger(ApplicationProtocol applicationProtocol) {
        this.applicationProtocol = applicationProtocol;
    }

    public void parse() {
        if (((Http) this.applicationProtocol).getVerb() != null)
            System.out.println("Verb: " + ((Http) this.applicationProtocol).getVerb());
        if (((Http) this.applicationProtocol).getPath() != null)
            System.out.println("Path: " + ((Http) this.applicationProtocol).getPath());
        if (((Http) this.applicationProtocol).getVersion() != null)
            System.out.println("Version: " + ((Http) this.applicationProtocol).getVersion());
        System.out.println("Application HTTP data: " + ((Http) this.applicationProtocol).getData());
    }
}
