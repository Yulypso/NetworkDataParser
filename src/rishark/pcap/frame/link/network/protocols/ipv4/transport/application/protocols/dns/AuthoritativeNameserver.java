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

    public AuthoritativeNameserver (String raw, String dnsRaw) {
        int isNotRoot = 0;
        if (Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 0, 1)) == 0) { // ROOT
            this.authoritativeNameserverName = "Root";
        } else {
            this.authoritativeNameserverName = Utils.hexStringToString(Utils.readBytesFromIndex(raw, 0, 2));
            isNotRoot = 1;
        }

        this.authoritativeNameserverType = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 1 + isNotRoot, 2));
        this.authoritativeNameserverClass = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 3 + isNotRoot, 2));
        this.timeToLive = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 5 + isNotRoot, 4));
        this.dataLength = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 9 + isNotRoot, 2));

        switch (authoritativeNameserverType) {
            case 2 -> {  // type = NS
                this.primaryNameServer = (Utils.readBytesFromIndex(raw, 11 + isNotRoot, dataLength));
                this.raw = Utils.readBytesFromIndex(raw, 11 + isNotRoot + dataLength, (raw.length() / 2) - (11 + isNotRoot + dataLength));
            }
            case 6 -> {  // type = SOA
                StringBuilder qn = new StringBuilder();
                String currRaw = raw;
                int nbChar = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 11 + isNotRoot, 1));
                currRaw = Utils.readBytesFromIndex(currRaw, 12 + isNotRoot, (currRaw.length() / 2) - (12 + isNotRoot));

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
                        this.primaryNameServer = qn.toString();
                    } else {
                        nbChar = Utils.hexStringToInt(Utils.readBytesFromIndex(currRaw, 0, 1));
                        currRaw = Utils.readBytesFromIndex(currRaw, 1, (currRaw.length() / 2) - 1);
                        this.primaryNameServer = qn.substring(0, qn.length() - 1);
                    }
                }

                StringBuilder sb = new StringBuilder();
                nbChar = Utils.hexStringToInt(Utils.readBytesFromIndex(currRaw, 0, 1));
                currRaw = Utils.readBytesFromIndex(currRaw, 1, (currRaw.length() / 2) - 1);
                while (nbChar != 0) {
                    for (int i = 0; i < nbChar; i++) {
                        sb.append(Utils.hexStringToString(Utils.readBytesFromIndex(currRaw, i, 1)));
                    }
                    sb.append(".");
                    currRaw = Utils.readBytesFromIndex(currRaw, nbChar, (currRaw.length() / 2) - nbChar);
                    if (("" + Utils.hexStringToBinary(Utils.readBytesFromIndex(currRaw, 0, 1)).charAt(0) + Utils.hexStringToBinary(Utils.readBytesFromIndex(currRaw, 0, 1)).charAt(1)).equals("11")) { // pointer detected
                        // TODO : debug this part later
                        nbChar = 0;
                        sb.append(Utils.readBytesFromIndex(currRaw, 0, 2)); // append pointer + pointer value
                        currRaw = Utils.readBytesFromIndex(currRaw, 2, (currRaw.length() / 2) - 2); // save pointer value
                        this.responsibleAuthorityMailbox = sb.toString();
                    } else {
                        nbChar = Utils.hexStringToInt(Utils.readBytesFromIndex(currRaw, 0, 1));
                        currRaw = Utils.readBytesFromIndex(currRaw, 1, (currRaw.length() / 2) - 1);
                        this.responsibleAuthorityMailbox = sb.substring(0, sb.length() - 1);
                    }
                }
                this.serialNumber = Utils.hexStringToLong(Utils.readBytesFromIndex(currRaw, 0, 4));
                this.refreshInterval = Utils.hexStringToLong(Utils.readBytesFromIndex(currRaw, 4, 4));
                this.retryInterval = Utils.hexStringToLong(Utils.readBytesFromIndex(currRaw, 8, 4));
                this.expireLimit = Utils.hexStringToLong(Utils.readBytesFromIndex(currRaw, 12, 4));
                this.minimumTTL = Utils.hexStringToLong(Utils.readBytesFromIndex(currRaw, 16, 4));
                this.raw = Utils.readBytesFromIndex(currRaw, 20, (currRaw.length() / 2) - 20);
            }
            default -> this.raw = Utils.readBytesFromIndex(raw, 11 + isNotRoot + dataLength, (raw.length() / 2) - (11 + isNotRoot + dataLength));
        }
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
