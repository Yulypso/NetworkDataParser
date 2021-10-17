package rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dns;

import utils.Utils;

public class Answer {

    private String answerName;
    private final int answerType;
    private final int answerClass;
    private final int timeToLive;
    private final int dataLength;
    private final String data;
    private final String raw;

    public Answer(String raw, String dnsRaw) {

        String currRaw = raw;
        String st = Utils.hexStringToBinary(Utils.readBytesFromIndex(raw, 0, 2));

        if (("" + st.charAt(0) + st.charAt(1)).equals("11")) { // pointeur signication
            this.answerName = Utils.readBytesFromIndex(currRaw, 0, 2);
            currRaw = Utils.readBytesFromIndex(currRaw, 2, (currRaw.length() / 2) - 2);
        } else {
            StringBuilder qn = new StringBuilder();

            int nbChar = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 0, 1));
            currRaw = Utils.readBytesFromIndex(currRaw, 1, (currRaw.length() / 2) - 1);

            while (nbChar != 0) {
                for (int i = 0; i < nbChar; i++) {
                    qn.append(Utils.hexStringToString(Utils.readBytesFromIndex(currRaw, i, 1)));
                }
                qn.append(".");
                currRaw = Utils.readBytesFromIndex(currRaw, nbChar, (currRaw.length() / 2) - nbChar);
                if (("" + Utils.hexStringToBinary(Utils.readBytesFromIndex(currRaw, 0, 1)).charAt(0) + Utils.hexStringToBinary(Utils.readBytesFromIndex(currRaw, 0, 1)).charAt(1)).equals("11")) { // pointer detected
                    // TODO : debug this part later
                    nbChar = 0;
                    qn.append(Utils.readBytesFromIndex(currRaw, 0, 2)); // append pointer + pointer value
                    currRaw = Utils.readBytesFromIndex(currRaw, 2, (currRaw.length() / 2) - 2); // save pointer value
                    this.answerName = qn.toString();
                } else {
                    nbChar = Utils.hexStringToInt(Utils.readBytesFromIndex(currRaw, 0, 1));
                    currRaw = Utils.readBytesFromIndex(currRaw, 1, (currRaw.length() / 2) - 1);
                    this.answerName = qn.substring(0, qn.length() - 1);
                }
            }
        }
        this.answerType = Utils.hexStringToInt(Utils.readBytesFromIndex(currRaw, 0, 2));
        this.answerClass = Utils.hexStringToInt(Utils.readBytesFromIndex(currRaw, 2, 2));
        this.timeToLive = Utils.hexStringToInt(Utils.readBytesFromIndex(currRaw, 4, 4));
        this.dataLength = Utils.hexStringToInt(Utils.readBytesFromIndex(currRaw, 8, 2));
        this.data = Utils.readBytesFromIndex(currRaw, 10, dataLength);

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
}
