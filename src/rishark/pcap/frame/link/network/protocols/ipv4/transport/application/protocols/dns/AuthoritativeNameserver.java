package rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dns;

import utils.Utils;

public class AuthoritativeNameserver {

    private final String authoritativeNameserverName;
    private final int authoritativeNameserverType;
    private final int authoritativeNameserverClass;
    private final int timeToLive;
    private final int dataLength;
    private String primaryNameServer; // == nameserver for NS
    private String responsibleAuthorityMailbox;
    private long serialNumber;
    private long refreshInterval;
    private long retryInterval;
    private long expireLimit;
    private long minimumTTL;

    private final String raw;

    public AuthoritativeNameserver (String raw, String queryName) {
        int isNS = 0;
        String st = Utils.hexStringToBinary(Utils.readBytesFromIndex(raw, 0, 2));
        if (("" + st.charAt(0) + st.charAt(1)).equals("11")){
            this.authoritativeNameserverName = queryName;
            isNS = 1;
        } else {
            this.authoritativeNameserverName = Utils.hexStringToString(Utils.readBytesFromIndex(raw, 0, 1));
        }

        this.authoritativeNameserverType = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 1 + isNS, 2));
        this.authoritativeNameserverClass = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 3 + isNS, 2));
        this.timeToLive = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 5 + isNS, 4));
        this.dataLength = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 9 + isNS, 2));

        if (authoritativeNameserverType == 2) { // type = NS
            this.primaryNameServer = (Utils.readBytesFromIndex(raw, 11 + isNS, dataLength));
            this.raw = Utils.readBytesFromIndex(raw, 11 + isNS + dataLength, (raw.length()/2) - (11 + isNS + dataLength));

        } else if (authoritativeNameserverType == 6){ // type = SOA
            StringBuilder qn = new StringBuilder();
            String currRaw = raw;
            int nbChar = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 11, 1));
            currRaw = Utils.readBytesFromIndex(currRaw,12, (currRaw.length()/2) - 12);

            System.out.println("type : " + authoritativeNameserverType);
            System.out.println(currRaw);

            while (nbChar != 0) {
                for (int i = 0; i < nbChar; i++) {
                    qn.append(Utils.hexStringToString(Utils.readBytesFromIndex(currRaw,  i, 1)));
                }
                qn.append(".");
                currRaw = Utils.readBytesFromIndex(currRaw,  nbChar, (currRaw.length()/2) - nbChar);
                nbChar = Utils.hexStringToInt(Utils.readBytesFromIndex(currRaw, 0, 1));
                currRaw = Utils.readBytesFromIndex(currRaw,  1, (currRaw.length()/2) - 1);
            }
            this.primaryNameServer = qn.substring(0, qn.length() - 1);

            StringBuilder sb = new StringBuilder();
            nbChar = Utils.hexStringToInt(Utils.readBytesFromIndex(currRaw, 0, 1));
            currRaw = Utils.readBytesFromIndex(currRaw,1, (currRaw.length()/2) - 1);
            while (nbChar != 0) {
                for (int i = 0; i < nbChar; i++) {
                    sb.append(Utils.hexStringToString(Utils.readBytesFromIndex(currRaw,  i, 1)));
                }
                sb.append(".");
                currRaw = Utils.readBytesFromIndex(currRaw,  nbChar, (currRaw.length()/2) - nbChar);
                nbChar = Utils.hexStringToInt(Utils.readBytesFromIndex(currRaw, 0, 1));
                currRaw = Utils.readBytesFromIndex(currRaw,  1, (currRaw.length()/2) - 1);
            }
            this.responsibleAuthorityMailbox = sb.substring(0, sb.length() - 1);
            this.serialNumber = Utils.hexStringToLong(Utils.readBytesFromIndex(currRaw, 0, 4));
            this.refreshInterval = Utils.hexStringToLong(Utils.readBytesFromIndex(currRaw, 4, 4));
            this.retryInterval = Utils.hexStringToLong(Utils.readBytesFromIndex(currRaw, 8, 4));
            this.expireLimit = Utils.hexStringToLong(Utils.readBytesFromIndex(currRaw, 12, 4));
            this.minimumTTL = Utils.hexStringToLong(Utils.readBytesFromIndex(currRaw, 16, 4));

            this.raw = Utils.readBytesFromIndex(currRaw, 20, (currRaw.length()/2) - 20);
        } else // other types untreated
            this.raw = Utils.readBytesFromIndex(raw, 11 + isNS + dataLength, (raw.length()/2) - (11 + isNS + dataLength));;
    }

    public String getAuthoritativeNameserverName() {
        return authoritativeNameserverName;
    }

    public int getAuthoritativeNameserverType() {
        return authoritativeNameserverType;
    }

    public int getAuthoritativeNameserverClass() {
        return authoritativeNameserverClass;
    }

    public int getTimeToLive() {
        return timeToLive;
    }

    public int getDataLength() {
        return dataLength;
    }

    public String getRaw() {
        return raw;
    }

    public String getPrimaryNameServer() {
        return primaryNameServer;
    }

    public String getResponsibleAuthorityMailbox() {
        return responsibleAuthorityMailbox;
    }

    public long getSerialNumber() {
        return serialNumber;
    }

    public long getRefreshInterval() {
        return refreshInterval;
    }

    public long getRetryInterval() {
        return retryInterval;
    }

    public long getExpireLimit() {
        return expireLimit;
    }

    public long getMinimumTTL() {
        return minimumTTL;
    }
}
