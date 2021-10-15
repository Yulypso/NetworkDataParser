package rishark.parser;

import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.ApplicationProtocol;
import utils.Utils;

public class DNSParser {

    private final ApplicationProtocol applicationProtocol;

    public DNSParser(ApplicationProtocol applicationProtocol) {
        this.applicationProtocol = applicationProtocol;
    }

    public void parse() {
        System.out.println("Application DNS raw: " + Utils.hexStringToString(this.applicationProtocol.getRaw()));
    }
}
