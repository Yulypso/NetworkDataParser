package rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dns;

import utils.Utils;

public class Answer {

    private final String answerName;
    private final int answerType;
    private final int answerClass;
    private final int timeToLive;
    private final int dataLength;
    private final String data;
    private final String raw;

    public Answer(String raw, String queryName) {

        String st = Utils.hexStringToBinary(Utils.readBytesFromIndex(raw, 0, 2));
        if (("" + st.charAt(0) + st.charAt(1)).equals("11")) // pointeur signication
            this.answerName = queryName;
        else
            this.answerName = Utils.hexStringToString(Utils.readBytesFromIndex(raw, 0, 2));
        this.answerType = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 2, 2));
        this.answerClass = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 4, 2));
        this.timeToLive = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 6, 4));

        this.dataLength = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 10, 2));
        this.data = Utils.readBytesFromIndex(raw, 12, dataLength);

        this.raw = Utils.readBytesFromIndex(raw, 12 + dataLength, (raw.length()/2) - (12 + dataLength));
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
}
