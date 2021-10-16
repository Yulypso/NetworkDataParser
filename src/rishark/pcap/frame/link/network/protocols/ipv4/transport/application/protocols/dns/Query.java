package rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dns;

import utils.Utils;

public class Query {

    private final String queryName;
    private final int queryType;
    private final int queryClass;

    private final String raw;


    public Query(String raw) {
        StringBuilder qn = new StringBuilder();
        String currRaw = raw;
        int nbChar = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 0, 1));
        currRaw = Utils.readBytesFromIndex(currRaw,1, (currRaw.length()/2) - 1);

        while (nbChar != 0) {
            for (int i = 0; i < nbChar; i++) {
                qn.append(Utils.hexStringToString(Utils.readBytesFromIndex(currRaw,  i, 1)));
            }
            qn.append(".");
            currRaw = Utils.readBytesFromIndex(currRaw,  nbChar, (currRaw.length()/2) - nbChar);
            nbChar = Utils.hexStringToInt(Utils.readBytesFromIndex(currRaw, 0, 1));
            currRaw = Utils.readBytesFromIndex(currRaw,  1, (currRaw.length()/2) - 1);
        }

        this.queryName = qn.substring(0, qn.length() - 1);
        this.queryType = Utils.hexStringToInt(Utils.readBytesFromIndex(currRaw, 0, 2));
        this.queryClass = Utils.hexStringToInt(Utils.readBytesFromIndex(currRaw, 2, 2));

        this.raw = Utils.readBytesFromIndex(currRaw, 4, (currRaw.length()/2) - 4);
    }


    public String getRaw() {
        return raw;
    }

    public String getQueryName() {
        return queryName;
    }

    public int getQueryType() {
        return queryType;
    }

    public int getQueryClass() {
        return queryClass;
    }
}
