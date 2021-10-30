package rishark.parser.parsers;

import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.ApplicationProtocol;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.http.Http;

public class HTTPParser {

    private final ApplicationProtocol applicationProtocol;

    public HTTPParser(ApplicationProtocol applicationProtocol) {
        this.applicationProtocol = applicationProtocol;
    }

    public void parse() {
        if (((Http) this.applicationProtocol).getVerb() != null)
            System.out.println("\t\tVerb: " + ((Http) this.applicationProtocol).getVerb());
        if (((Http) this.applicationProtocol).getPath() != null)
            System.out.println("\t\tPath: " + ((Http) this.applicationProtocol).getPath());
        if (((Http) this.applicationProtocol).getVersion() != null)
            System.out.println("\t\tVersion: " + ((Http) this.applicationProtocol).getVersion());
        System.out.println("\t\tApplication HTTP data: \n\t\t\t\t" + ((Http) this.applicationProtocol).getData().replaceAll("\n", "\n\t\t\t\t"));
    }
}
