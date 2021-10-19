package rishark.parser;

import rishark.pcap.frame.link.network.Protocol;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.ApplicationProtocol;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dns.DNSClass;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dns.DNSType;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dns.Dns;

import java.util.Objects;

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

        if (((Dns) this.applicationProtocol).getNbQuestions() > 0)
            System.out.println("Queries: ");
        for (int i = 0; i < ((Dns) this.applicationProtocol).getNbQuestions() ; i++) {
            System.out.println("\t- " + ((Dns) this.applicationProtocol).getQueryList().get(i).getQueryName() +
                    ", Type: " + DNSType.findDnsType(((Dns) this.applicationProtocol).getQueryList().get(i).getQueryType()) +
                    ", Class: " + DNSClass.findDnsClass(((Dns) this.applicationProtocol).getQueryList().get(i).getQueryClass()));
        }

        if (((Dns) this.applicationProtocol).getNbAnswers() > 0)
            System.out.println("Answers: ");
        for (int i = 0; i < ((Dns) this.applicationProtocol).getNbAnswers() ; i++) {
            System.out.println("\t- " + ((Dns) this.applicationProtocol).getAnswerList().get(i).getAnswerName() +
                    ", Type: " + DNSType.findDnsType(((Dns) this.applicationProtocol).getAnswerList().get(i).getAnswerType()) +
                    ", Class: " + DNSClass.findDnsClass(((Dns) this.applicationProtocol).getAnswerList().get(i).getAnswerClass()));
            System.out.println("\t  Time to live: " + ((Dns) this.applicationProtocol).getAnswerList().get(i).getTimeToLive());
            System.out.println("\t  Data length: " + ((Dns) this.applicationProtocol).getAnswerList().get(i).getDataLength());

            switch (Objects.requireNonNull(DNSType.findDnsType(((Dns) this.applicationProtocol).getAnswerList().get(i).getAnswerType()))) {
                case A -> System.out.println("\t  Address: " + ((Dns) this.applicationProtocol).getAnswerList().get(i).getData());
                case MX -> {
                    System.out.println("\t  Preference: " + ((Dns) this.applicationProtocol).getAnswerList().get(i).getPreference());
                    System.out.println("\t  Data: " + ((Dns) this.applicationProtocol).getAnswerList().get(i).getData());
                }
                default -> System.out.println("\t  Data: " + ((Dns) this.applicationProtocol).getAnswerList().get(i).getData());
            }
        }

        if (((Dns) this.applicationProtocol).getNbAuthority() > 0)
            System.out.println("Authoritative Nameserver: ");
        for (int i = 0; i < ((Dns) this.applicationProtocol).getNbAuthority() ; i++) {
            System.out.println("\t- " + ((Dns) this.applicationProtocol).getAuthoritativeNameserverList().get(i).getAuthoritativeNameserverName() +
                    ", Type: " + DNSType.findDnsType(((Dns) this.applicationProtocol).getAuthoritativeNameserverList().get(i).getAuthoritativeNameserverType()) +
                    ", Class: " + DNSClass.findDnsClass(((Dns) this.applicationProtocol).getAuthoritativeNameserverList().get(i).getAuthoritativeNameserverClass()));
            System.out.println("\t  Time to live: " + ((Dns) this.applicationProtocol).getAuthoritativeNameserverList().get(i).getTimeToLive());
            System.out.println("\t  Data length: " + ((Dns) this.applicationProtocol).getAuthoritativeNameserverList().get(i).getDataLength());

            switch (Objects.requireNonNull(DNSType.findDnsType(((Dns) this.applicationProtocol).getAuthoritativeNameserverList().get(i).getAuthoritativeNameserverType()))) {
                case NS -> System.out.println("\t  Primary name server: " + ((Dns) this.applicationProtocol).getAuthoritativeNameserverList().get(i).getPrimaryNameServer());
                case SOA -> {
                    System.out.println("\t  Primary name server: " + ((Dns) this.applicationProtocol).getAuthoritativeNameserverList().get(i).getPrimaryNameServer());
                    System.out.println("\t  Responsible authority's mailbox: " + ((Dns) this.applicationProtocol).getAuthoritativeNameserverList().get(i).getResponsibleAuthorityMailbox());
                    System.out.println("\t  Serial number: " + ((Dns) this.applicationProtocol).getAuthoritativeNameserverList().get(i).getSerialNumber());
                    System.out.println("\t  Refresh interval: " + ((Dns) this.applicationProtocol).getAuthoritativeNameserverList().get(i).getRefreshInterval());
                    System.out.println("\t  Retry interval: " + ((Dns) this.applicationProtocol).getAuthoritativeNameserverList().get(i).getRetryInterval());
                    System.out.println("\t  Expire limit: " + ((Dns) this.applicationProtocol).getAuthoritativeNameserverList().get(i).getExpireLimit());
                    System.out.println("\t  Minimum TTL: " + ((Dns) this.applicationProtocol).getAuthoritativeNameserverList().get(i).getMinimumTTL());
                }
            }
        }

        if (((Dns) this.applicationProtocol).getNbAdditional() > 0)
            System.out.println("Additional Records: ");
        for (int i = 0; i < ((Dns) this.applicationProtocol).getNbAdditional() ; i++) {
            System.out.println("\t- " + ((Dns) this.applicationProtocol).getAdditionalRecordList().get(i).getAdditionalRecordName() +
                    ", Type: " + DNSType.findDnsType(((Dns) this.applicationProtocol).getAdditionalRecordList().get(i).getAdditionalRecordType()));
            switch (Objects.requireNonNull(DNSType.findDnsType(((Dns) this.applicationProtocol).getAdditionalRecordList().get(i).getAdditionalRecordType()))) {
                case A -> {
                    System.out.println("\t  Class: " + DNSClass.findDnsClass(((Dns) this.applicationProtocol).getAdditionalRecordList().get(i).getAdditonalRecordClass()));
                    System.out.println("\t  Time to live: " + ((Dns) this.applicationProtocol).getAdditionalRecordList().get(i).getTtl());
                }
                case OPT -> {
                    System.out.println("\t  UDP Payload size: " + ((Dns) this.applicationProtocol).getAdditionalRecordList().get(i).getPayloadSize());
                    System.out.println("\t  Higher bits in extended RCODE: " + ((Dns) this.applicationProtocol).getAdditionalRecordList().get(i).getHigherBitExtendedRCODE());
                    System.out.println("\t  EDNS0 version: " + ((Dns) this.applicationProtocol).getAdditionalRecordList().get(i).getEDNS0Version());
                    System.out.println("\t  z: " + ((Dns) this.applicationProtocol).getAdditionalRecordList().get(i).getZ());
                }
            }
            System.out.println("\t  Data length: " + ((Dns) this.applicationProtocol).getAdditionalRecordList().get(i).getDataLength());
            if(((Dns) this.applicationProtocol).getAdditionalRecordList().get(i).getDataLength() > 0 )
                System.out.println("\t  Data: " + ((Dns) this.applicationProtocol).getAdditionalRecordList().get(i).getData());
        }
        if (this.applicationProtocol.getRaw().length() > 0)
            System.out.println("Application DNS raw: " + this.applicationProtocol.getRaw());
    }
}
