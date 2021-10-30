package rishark.parser.parsers;

import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.ApplicationProtocol;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.ftp.Ftp;

public class FTPParser {

    private final ApplicationProtocol applicationProtocol;

    public FTPParser(ApplicationProtocol ftp) {
        this.applicationProtocol = ftp;
    }

    public void parse() {
        if (((Ftp)this.applicationProtocol).getRequestCommand() != null) {
            System.out.println("\t\tRequest command: " + ((Ftp)this.applicationProtocol).getRequestCommand());
            System.out.println("\t\tRequest arguments: " + ((Ftp)this.applicationProtocol).getArguments());
        } else if (((Ftp)this.applicationProtocol).getResponseCode() != null) {
            System.out.println("\t\tResponse code: " + ((Ftp)this.applicationProtocol).getResponseCode());
            System.out.println("\t\tResponse arguments: " + ((Ftp)this.applicationProtocol).getArguments());
        }
        if (this.applicationProtocol.getRaw().length() > 0)
            System.out.println("\t\tApplication FTP raw: " + this.applicationProtocol.getRaw());
    }
}
