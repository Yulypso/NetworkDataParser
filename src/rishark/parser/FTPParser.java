package rishark.parser;

import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.ApplicationProtocol;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.ftp.Ftp;
import utils.Utils;

public class FTPParser {

    private final ApplicationProtocol applicationProtocol;

    public FTPParser(ApplicationProtocol ftp) {
        this.applicationProtocol = ftp;
    }

    public void parse() {
        if (((Ftp)this.applicationProtocol).getRequestCommand() != null) {
            System.out.println("Request command: " + ((Ftp)this.applicationProtocol).getRequestCommand());
            System.out.println("Request arguments: " + ((Ftp)this.applicationProtocol).getArguments());
        } else if (((Ftp)this.applicationProtocol).getResponseCode() != null) {
            System.out.println("Response code: " + ((Ftp)this.applicationProtocol).getResponseCode());
            System.out.println("Response arguments: " + ((Ftp)this.applicationProtocol).getArguments());
        }
        if (this.applicationProtocol.getRaw().length() > 0)
            System.out.println("Application FTP raw: " + this.applicationProtocol.getRaw());
    }
}
