package rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dns;

import rishark.pcap.frame.link.network.Protocol;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.ApplicationProtocol;
import utils.Utils;

import java.util.ArrayList;
import java.util.List;

public class Dns implements ApplicationProtocol { // new 7 OPT || Rishark 170

    private final long length;
    private final String transactionId;
    private final String flagResponse;
    private final String flagOpCode;
    private final String flagAuthoritative;
    private final String flagTruncated;
    private final String flagRecursionDesired;
    private final String flagRecursionAvailable;
    private final String flagZ;
    private final String flagAnswerAuthenticated;
    private final String flagNonAuthenticatedData;
    private final String flagReplyCode;
    private final int nbQuestions;
    private final int nbAnswers;
    private final int nbAuthority;
    private final int nbAdditional;

    private final List<Query> queryList;
    private final List<Answer> answerList;
    private final List<AuthoritativeNameserver> authoritativeNameserverList;
    private final List<AdditionalRecord> additionalRecordList;

    private final String raw;
    private final Protocol overProtocol;

    public Dns(String raw, Protocol overProtocol, long udpDataLength) {
        this.overProtocol = overProtocol;
        this.queryList = new ArrayList<>();
        this.answerList = new ArrayList<>();
        this.authoritativeNameserverList = new ArrayList<>();
        this.additionalRecordList = new ArrayList<>();

        int isUDP;
        if(overProtocol == Protocol.TCP) {
            this.length = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 0, 2));
            isUDP = 0;
        }
        else {
            this.length = udpDataLength;
            isUDP = 2;
        }

        this.transactionId = Utils.readBytesFromIndex(raw, 2 - isUDP, 2);
        String flag = Utils.hexStringToBinary(Utils.readBytesFromIndex(raw, 4 - isUDP, 2));
        this.flagResponse = "" + flag.charAt(0);
        this.flagOpCode = "" + flag.charAt(1) + flag.charAt(2) + flag.charAt(3) + flag.charAt(4);
        this.flagAuthoritative = "" + flag.charAt(5);
        this.flagTruncated = "" + flag.charAt(6);
        this.flagRecursionDesired = "" + flag.charAt(7);
        this.flagRecursionAvailable = "" + flag.charAt(8);
        this.flagZ = "" + flag.charAt(9);
        this.flagAnswerAuthenticated = "" + flag.charAt(10);
        this.flagNonAuthenticatedData = "" + flag.charAt(11);
        this.flagReplyCode = "" + flag.charAt(12) + flag.charAt(13) + flag.charAt(14) + flag.charAt(15);
        this.nbQuestions = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 6 - isUDP, 2));
        this.nbAnswers = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 8 - isUDP, 2));
        this.nbAuthority = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 10 - isUDP, 2));
        this.nbAdditional = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 12 - isUDP, 2));

        String currentRaw = Utils.readBytesFromIndex(raw, 14 - isUDP, (raw.length()/2) - (14 - isUDP));

        for (int i = 0; i < nbQuestions; i++) {
            System.out.println("nb query: " + nbQuestions + " nb: " + i);
            System.out.println(currentRaw);
            Query query = new Query(currentRaw, raw);
            this.queryList.add(query);
            currentRaw = query.getRaw();
        }
        for (int i = 0; i < nbAnswers; i++) {
            System.out.println("nb nbanswer: " + nbAnswers + " nb: " + i);
            System.out.println(currentRaw);
            Answer answer = new Answer(currentRaw, raw, overProtocol);
            this.answerList.add(answer);
            currentRaw = answer.getRaw();
        }
        for (int i = 0; i < nbAuthority; i++) {
            System.out.println("nb authority: " + nbAuthority + " nb: " + i);
            System.out.println(currentRaw);
            AuthoritativeNameserver authoritativeNameserver = new AuthoritativeNameserver(currentRaw, raw);
            this.authoritativeNameserverList.add(authoritativeNameserver);
            currentRaw = authoritativeNameserver.getRaw();
        }
        for (int i = 0; i < nbAdditional; i++) {
            AdditionalRecord additionalRecord = new AdditionalRecord(currentRaw, raw);
            this.additionalRecordList.add(additionalRecord);
            currentRaw = additionalRecord.getRaw();
        }
        this.raw = currentRaw; // starts from nb additional
    }

    @Override
    public String getRaw() {
        return raw;
    }

    @Override
    public Protocol getOverProtocol() {
        return overProtocol;
    }

    public long getLength() {
        return length;
    }

    public String getTransactionId() {
        return transactionId;
    }

    public String getFlagResponse() {
        return flagResponse;
    }

    public String getFlagOpCode() {
        return flagOpCode;
    }

    public String getFlagAuthoritative() {
        return flagAuthoritative;
    }

    public String getFlagTruncated() {
        return flagTruncated;
    }

    public String getFlagRecursionDesired() {
        return flagRecursionDesired;
    }

    public String getFlagRecursionAvailable() {
        return flagRecursionAvailable;
    }

    public String getFlagZ() {
        return flagZ;
    }

    public String getFlagAnswerAuthenticated() {
        return flagAnswerAuthenticated;
    }

    public String getFlagNonAuthenticatedData() {
        return flagNonAuthenticatedData;
    }

    public String getFlagReplyCode() {
        return flagReplyCode;
    }

    public int getNbQuestions() {
        return nbQuestions;
    }

    public int getNbAnswers() {
        return nbAnswers;
    }

    public int getNbAuthority() {
        return nbAuthority;
    }

    public int getNbAdditional() {
        return nbAdditional;
    }

    public List<Query> getQueryList() {
        return queryList;
    }

    public List<Answer> getAnswerList() {
        return answerList;
    }

    public List<AuthoritativeNameserver> getAuthoritativeNameserverList() {
        return authoritativeNameserverList;
    }

    public List<AdditionalRecord> getAdditionalRecordList() {
        return additionalRecordList;
    }
}
