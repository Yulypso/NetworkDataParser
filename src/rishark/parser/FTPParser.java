package rishark.parser;

import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.ApplicationProtocol;
import utils.Utils;

public class FTPParser {

    private final ApplicationProtocol applicationProtocol;

    public FTPParser(ApplicationProtocol ftp) {
        this.applicationProtocol = ftp;
    }

    public void parse() {
        System.out.println("Application raw: " + Utils.hexStringToString(this.applicationProtocol.getRaw()));
    }
}
