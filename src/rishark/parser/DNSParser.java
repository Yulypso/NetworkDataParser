package rishark.parser;

import rishark.pcap.frame.link.network.Protocol;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.ApplicationProtocol;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dns.Dns;

import utils.Utils;

public class DNSParser {

    private final ApplicationProtocol applicationProtocol;

    public DNSParser(ApplicationProtocol applicationProtocol) {
        this.applicationProtocol = applicationProtocol;
    }

    public void parse() {
        if (this.applicationProtocol.getOverProtocol() == Protocol.TCP)
            System.out.println("Length: " + ((Dns) this.applicationProtocol).getLength());
        System.out.println("Transaction ID:  " + ((Dns) this.applicationProtocol).getTransactionId());
        System.out.println("Flags: ");
        System.out.println("\t- Response: " + ((Dns) this.applicationProtocol).getFlagResponse());
        System.out.println("\t- Opcode: " + ((Dns) this.applicationProtocol).getFlagOpCode());
        System.out.println("\t- Authoritative: " + ((Dns) this.applicationProtocol).getFlagAuthoritative());
        System.out.println("\t- Truncated: " + ((Dns) this.applicationProtocol).getFlagTruncated());
        System.out.println("\t- Recursion desired: " + ((Dns) this.applicationProtocol).getFlagRecursionDesired());
        System.out.println("\t- Recursion available: " + ((Dns) this.applicationProtocol).getFlagRecursionAvailable());
        System.out.println("\t- Z: " + ((Dns) this.applicationProtocol).getFlagZ());
        System.out.println("\t- Answer authenticated: " + ((Dns) this.applicationProtocol).getFlagAnswerAuthenticated());
        System.out.println("\t- Answer Non authenticated data: " + ((Dns) this.applicationProtocol).getFlagNonAuthenticatedData());
        System.out.println("\t- Reply Code: " + ((Dns) this.applicationProtocol).getFlagReplyCode());
        System.out.println("Number of questions: " + ((Dns) this.applicationProtocol).getNbQuestions());
        System.out.println("Number of answers: " + ((Dns) this.applicationProtocol).getNbAnswers());
        System.out.println("Number of Authoritative nameservers: " + ((Dns) this.applicationProtocol).getNbAuthority());
        System.out.println("Number of Additional records: " + ((Dns) this.applicationProtocol).getNbAdditional());
        System.out.println("Queries: ");

        for (int i = 0; i < ((Dns) this.applicationProtocol).getNbQuestions() ; i++) {
            System.out.println("\t- " + ((Dns) this.applicationProtocol).getQueryList().get(i).getQueryName() +
                    ", Type: " + ((Dns) this.applicationProtocol).getQueryList().get(i).getQueryType() +
                    ", Class: " + ((Dns) this.applicationProtocol).getQueryList().get(i).getQueryClass());
        }
        System.out.println("Application DNS raw: " + Utils.hexStringToString(this.applicationProtocol.getRaw()));

    }
}
