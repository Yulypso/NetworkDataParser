package rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dns;

import rishark.pcap.frame.link.network.Protocol;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.ApplicationProtocol;
import utils.Utils;

public class Dns implements ApplicationProtocol {

    private final int length;
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

    private final String raw;
    private final Protocol overProtocol;

    public Dns(String raw, Protocol overProtocol) {
        this.overProtocol = overProtocol;
        if(overProtocol == Protocol.TCP)
            this.length = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 0, 2));
        else
            this.length = 0; // TODO : calculer dynamiquement pour UDP ?

        this.transactionId = Utils.readBytesFromIndex(raw, 2, 2);
        String flag = Utils.hexStringToBinary(Utils.readBytesFromIndex(raw, 4, 2));
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
        this.nbQuestions = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 6, 2));
        this.nbAnswers = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 8, 2));
        this.nbAuthority = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 10, 2));
        this.nbAdditional = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 12, 2));



        this.raw =  Utils.readBytesFromIndex(raw, 14, (raw.length()/2) - 14); // starts from nb additional
    }

    public String getRaw() {
        return raw;
    }

    @Override
    public Protocol getOverProtocol() {
        return overProtocol;
    }

    public int getLength() {
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
}
