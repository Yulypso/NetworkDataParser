package rishark.parser.parsers;

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
        System.out.print("\t\tTransaction ID:  " + ((Dns) this.applicationProtocol).getTransactionId());
        System.out.print("\t\t\t\t\tNumber of Queries: " + ((Dns) this.applicationProtocol).getNbQuestions());
        System.out.println("\t\t\t\t\tNumber of Authoritative nameservers: " + ((Dns) this.applicationProtocol).getNbAuthority());
        System.out.print("\t\tNumber of Answers: " + ((Dns) this.applicationProtocol).getNbAnswers());
        System.out.println("\t\t\t\t\tNumber of Additional records: " + ((Dns) this.applicationProtocol).getNbAdditional());

        if (((Dns) this.applicationProtocol).getNbQuestions() > 0)
            System.out.println("\tQueries: ");
        for (int i = 0; i < ((Dns) this.applicationProtocol).getNbQuestions() ; i++) {
            System.out.println("\t\t- " + ((Dns) this.applicationProtocol).getQueryList().get(i).getQueryName() +
                    ", Type: " + DNSType.findDnsType(((Dns) this.applicationProtocol).getQueryList().get(i).getQueryType()) +
                    ", Class: " + DNSClass.findDnsClass(((Dns) this.applicationProtocol).getQueryList().get(i).getQueryClass()));
        }

        if (((Dns) this.applicationProtocol).getNbAnswers() > 0)
            System.out.println("\tAnswers: ");
        for (int i = 0; i < ((Dns) this.applicationProtocol).getNbAnswers() ; i++) {
            System.out.print("\t\t- " + ((Dns) this.applicationProtocol).getAnswerList().get(i).getAnswerName() +
                    ", Type: " + DNSType.findDnsType(((Dns) this.applicationProtocol).getAnswerList().get(i).getAnswerType()) +
                    ", Class: " + DNSClass.findDnsClass(((Dns) this.applicationProtocol).getAnswerList().get(i).getAnswerClass()));

            switch (Objects.requireNonNull(DNSType.findDnsType(((Dns) this.applicationProtocol).getAnswerList().get(i).getAnswerType()))) {
                case A -> System.out.println("\t\tAddress: " + ((Dns) this.applicationProtocol).getAnswerList().get(i).getData());
                case MX -> System.out.println("\t\t\tData: " + ((Dns) this.applicationProtocol).getAnswerList().get(i).getData());
                default -> System.out.println("");
            }
        }

        if (((Dns) this.applicationProtocol).getNbAuthority() > 0)
            System.out.println("\tAuthoritative Nameserver: ");
        for (int i = 0; i < ((Dns) this.applicationProtocol).getNbAuthority() ; i++) {
            System.out.print("\t\t- " + ((Dns) this.applicationProtocol).getAuthoritativeNameserverList().get(i).getAuthoritativeNameserverName() +
                    ", Type: " + DNSType.findDnsType(((Dns) this.applicationProtocol).getAuthoritativeNameserverList().get(i).getAuthoritativeNameserverType()) +
                    ", Class: " + DNSClass.findDnsClass(((Dns) this.applicationProtocol).getAuthoritativeNameserverList().get(i).getAuthoritativeNameserverClass()));

            switch (Objects.requireNonNull(DNSType.findDnsType(((Dns) this.applicationProtocol).getAuthoritativeNameserverList().get(i).getAuthoritativeNameserverType()))) {
                case NS -> System.out.println("\t\tPrimary name server: " + ((Dns) this.applicationProtocol).getAuthoritativeNameserverList().get(i).getPrimaryNameServer());
                case SOA -> {
                    System.out.print("\t\tPrimary name server: " + ((Dns) this.applicationProtocol).getAuthoritativeNameserverList().get(i).getPrimaryNameServer());
                    System.out.println("\t\tResponsible authority's mailbox: " + ((Dns) this.applicationProtocol).getAuthoritativeNameserverList().get(i).getResponsibleAuthorityMailbox());
                    System.out.print("\t\t  Serial number: " + ((Dns) this.applicationProtocol).getAuthoritativeNameserverList().get(i).getSerialNumber());
                    System.out.print("\t\t\tRefresh interval: " + ((Dns) this.applicationProtocol).getAuthoritativeNameserverList().get(i).getRefreshInterval());
                    System.out.print("\t\t\tRetry interval: " + ((Dns) this.applicationProtocol).getAuthoritativeNameserverList().get(i).getRetryInterval());
                    System.out.print("\t\t\tExpire limit: " + ((Dns) this.applicationProtocol).getAuthoritativeNameserverList().get(i).getExpireLimit());
                    System.out.println("\t\t\tMinimum TTL: " + ((Dns) this.applicationProtocol).getAuthoritativeNameserverList().get(i).getMinimumTTL());
                }
            }
        }

        if (((Dns) this.applicationProtocol).getNbAdditional() > 0)
            System.out.println("\tAdditional Records: ");
        for (int i = 0; i < ((Dns) this.applicationProtocol).getNbAdditional() ; i++) {
            System.out.print("\t\t- " + ((Dns) this.applicationProtocol).getAdditionalRecordList().get(i).getAdditionalRecordName() +
                    ", Type: " + DNSType.findDnsType(((Dns) this.applicationProtocol).getAdditionalRecordList().get(i).getAdditionalRecordType()));
            switch (Objects.requireNonNull(DNSType.findDnsType(((Dns) this.applicationProtocol).getAdditionalRecordList().get(i).getAdditionalRecordType()))) {
                case A -> System.out.println("\t\t\t\tClass: " + DNSClass.findDnsClass(((Dns) this.applicationProtocol).getAdditionalRecordList().get(i).getAdditonalRecordClass()));
            }
        }
    }
}
