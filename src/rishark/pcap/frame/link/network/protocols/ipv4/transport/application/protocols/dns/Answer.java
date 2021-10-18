package rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dns;

import utils.Utils;

import java.util.Objects;

public class Answer {

    private String answerName;
    private final int answerType;
    private final int answerClass;
    private final int timeToLive;
    private final int dataLength;
    private String preference;
    private String data;
    private final String raw;

    public Answer(String raw, String dnsRaw) {

        String currRaw = raw;
        String st = Utils.hexStringToBinary(Utils.readBytesFromIndex(raw, 0, 2));

        if (("" + st.charAt(0) + st.charAt(1)).equals("11")) { // pointeur signication
            this.answerName = Utils.readBytesFromIndex(currRaw, 0, 2);
            currRaw = Utils.readBytesFromIndex(currRaw, 2, (currRaw.length() / 2) - 2);
        } else {
            this.answerName = Utils.readDataNameFromTmpRaw(currRaw);

            int readLength = 0;
            if (this.answerName != null && !this.answerName.contains("c0"))
                readLength = this.answerName.length() + 2;
            else if (this.answerName != null && this.answerName.contains("c0"))
                readLength = this.answerName.length() - 2;
            currRaw = Utils.readBytesFromIndex(currRaw, readLength, (currRaw.length() / 2) - readLength);
        }
        this.answerType = Utils.hexStringToInt(Utils.readBytesFromIndex(currRaw, 0, 2));
        this.answerClass = Utils.hexStringToInt(Utils.readBytesFromIndex(currRaw, 2, 2));
        this.timeToLive = Utils.hexStringToInt(Utils.readBytesFromIndex(currRaw, 4, 4));
        this.dataLength = Utils.hexStringToInt(Utils.readBytesFromIndex(currRaw, 8, 2));

        switch (Objects.requireNonNull(DNSType.findDnsType(answerType))) {
            case A -> this.data = Utils.bytesToIPv4(Utils.readBytesFromIndex(currRaw, 10, dataLength));
            case AAAA -> this.data = Utils.bytesToIPv6(Utils.readBytesFromIndex(currRaw, 10, dataLength));
            case MX -> {
                this.preference = Utils.readBytesFromIndex(currRaw, 10, 2);
                String tmpRaw = Utils.readBytesFromIndex(currRaw, 12, dataLength - 2);
                this.data = Utils.readDataNameFromTmpRaw(tmpRaw);
            }
            case CNAME -> {
                String tmpRaw = Utils.readBytesFromIndex(currRaw, 10, dataLength);
                this.data = Utils.readDataNameFromTmpRaw(tmpRaw);
            }
        }
        this.raw = Utils.readBytesFromIndex(currRaw, 10 + dataLength, (currRaw.length()/2) - (10 + dataLength));
    }

    public String getRaw() {
        return raw;
    }

    public String getAnswerName() {
        return answerName;
    }

    public int getAnswerType() {
        return answerType;
    }

    public int getAnswerClass() {
        return answerClass;
    }

    public int getTimeToLive() {
        return timeToLive;
    }

    public int getDataLength() {
        return dataLength;
    }

    public String getData() {
        return data;
    }

    public String getPreference() {
        return preference;
    }
}
