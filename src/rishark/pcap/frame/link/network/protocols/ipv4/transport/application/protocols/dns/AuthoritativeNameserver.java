package rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dns;

import utils.Utils;

import java.util.Objects;

public class AuthoritativeNameserver { // TODO : totodns.pcap 232

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
            isNotRoot = 1;
            String authoritativeNameserverNameTmp = Utils.readBytesFromIndex(raw, 0, 2);
            authoritativeNameserverNameTmp = Utils.readNamePointer(dnsRaw, authoritativeNameserverNameTmp);
            while (Utils.verifyPointerInName(authoritativeNameserverNameTmp))
                authoritativeNameserverNameTmp = Utils.readNamePointer(dnsRaw, authoritativeNameserverNameTmp);
            this.authoritativeNameserverName = authoritativeNameserverNameTmp;
        }

        this.authoritativeNameserverType = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 1 + isNotRoot, 2));
        this.authoritativeNameserverClass = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 3 + isNotRoot, 2));
        this.timeToLive = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 5 + isNotRoot, 4));
        this.dataLength = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 9 + isNotRoot, 2));

        switch (Objects.requireNonNull(DNSType.findDnsType(authoritativeNameserverType))) {
            case NS -> {
                this.primaryNameServer = (Utils.readBytesFromIndex(raw, 11 + isNotRoot, dataLength));
                this.raw = Utils.readBytesFromIndex(raw, 11 + isNotRoot + dataLength, (raw.length() / 2) - (11 + isNotRoot + dataLength));
            }
            case SOA -> {
                String tmpRaw = Utils.readBytesFromIndex(raw, 11 + isNotRoot, (raw.length() / 2) - (11 + isNotRoot));
                String st = Utils.hexStringToBinary(Utils.readBytesFromIndex(tmpRaw, 0, 2));
                int readLength = 0;

                String primaryNameServerTmp;
                if (st.startsWith("11")) {
                    primaryNameServerTmp = Utils.readNamePointer(dnsRaw, tmpRaw);
                    readLength += 2;

                    while (Utils.verifyPointerInName(primaryNameServerTmp)) {
                        primaryNameServerTmp = Utils.readNamePointer(dnsRaw, primaryNameServerTmp);
                        readLength += 2;
                    }
                } else {
                    primaryNameServerTmp = Utils.readDataNameFromTmpRaw(tmpRaw);
                    if(Utils.verifyPointerInName(primaryNameServerTmp))
                        readLength = primaryNameServerTmp.length() - 2;
                    else
                        readLength = primaryNameServerTmp.length() + 2; //null byte
                    while (Utils.verifyPointerInName(primaryNameServerTmp)) {
                        primaryNameServerTmp = Utils.readNamePointer(dnsRaw, primaryNameServerTmp);
                    }
                }
                this.primaryNameServer = primaryNameServerTmp;

                tmpRaw = Utils.readBytesFromIndex(tmpRaw, readLength, (tmpRaw.length() / 2) - readLength);
                st = Utils.hexStringToBinary(Utils.readBytesFromIndex(tmpRaw, 0, 2));
                readLength = 0;

                String responsibleAuthorityMailboxTmp;
                if (st.startsWith("11")) {
                    responsibleAuthorityMailboxTmp = Utils.readNamePointer(dnsRaw, tmpRaw);
                    readLength += 2;

                    while (Utils.verifyPointerInName(responsibleAuthorityMailboxTmp)) {
                        responsibleAuthorityMailboxTmp = Utils.readNamePointer(dnsRaw, responsibleAuthorityMailboxTmp);
                        readLength += 2;
                    }
                } else {
                    responsibleAuthorityMailboxTmp = Utils.readDataNameFromTmpRaw(tmpRaw);
                    if(Utils.verifyPointerInName(responsibleAuthorityMailboxTmp))
                        readLength = responsibleAuthorityMailboxTmp.length() - 2;
                    else
                        readLength = responsibleAuthorityMailboxTmp.length() + 2; //null byte
                    while (Utils.verifyPointerInName(responsibleAuthorityMailboxTmp)) {
                        responsibleAuthorityMailboxTmp = Utils.readNamePointer(dnsRaw, responsibleAuthorityMailboxTmp);
                    }
                }
                this.responsibleAuthorityMailbox = responsibleAuthorityMailboxTmp;

                tmpRaw = Utils.readBytesFromIndex(tmpRaw, readLength, (tmpRaw.length() / 2) - readLength);

                this.serialNumber = Utils.hexStringToLong(Utils.readBytesFromIndex(tmpRaw, 0, 4));
                this.refreshInterval = Utils.hexStringToLong(Utils.readBytesFromIndex(tmpRaw, 4, 4));
                this.retryInterval = Utils.hexStringToLong(Utils.readBytesFromIndex(tmpRaw, 8, 4));
                this.expireLimit = Utils.hexStringToLong(Utils.readBytesFromIndex(tmpRaw, 12, 4));
                this.minimumTTL = Utils.hexStringToLong(Utils.readBytesFromIndex(tmpRaw, 16, 4));
                this.raw = Utils.readBytesFromIndex(tmpRaw, 20, (tmpRaw.length() / 2) - 20);
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
