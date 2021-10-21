package rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dns;

import utils.Utils;

import java.util.Objects;

public class AdditionalRecord { //new.pcap n°7

    private final String additionalRecordName;    // 1/2 bytes
    private final int additionalRecordType;         // 2 bytes

    private int additonalRecordClass;
    private long ttl;

    private int payloadSize;                  // 2 bytes
    private int higherBitExtendedRCODE;       // 1 byte
    private int EDNS0Version;                 // 1 byte
    private int z;                            // 2 bytes
    private int dataLength;                   // 2 bytes
    private String data;                      // datalength bytes

    private final String raw;

    public AdditionalRecord (String raw, String dnsRaw) {
        int isNotRoot = 0;
        if (Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 0, 1)) == 0) { // ROOT
            this.additionalRecordName = "Root";
        } else {
            this.additionalRecordName = Utils.readBytesFromIndex(raw, 0, 2);
            isNotRoot = 1;
        }
        this.additionalRecordType = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 1 + isNotRoot, 2));

        switch (Objects.requireNonNull(DNSType.findDnsType(additionalRecordType))) {
            case A -> {
                this.additonalRecordClass = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 3 + isNotRoot, 2));
                this.ttl = Utils.hexStringToLong(Utils.readBytesFromIndex(raw, 5 + isNotRoot, 4));
                this.dataLength = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 9 + isNotRoot, 2));
                this.data = Utils.readBytesFromIndex(raw, 11 + isNotRoot, dataLength);
                this.raw = Utils.readBytesFromIndex(raw, 11 + isNotRoot + dataLength, (raw.length() / 2) - (11 + isNotRoot + dataLength));
            }
            case OPT -> {
                this.payloadSize = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 3 + isNotRoot, 2));
                this.higherBitExtendedRCODE = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 5 + isNotRoot, 1));
                this.EDNS0Version = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 6 + isNotRoot, 1));
                this.z = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 7 + isNotRoot, 2));
                this.dataLength = Utils.hexStringToInt(Utils.readBytesFromIndex(raw, 9 + isNotRoot, 2));
                this.data = Utils.readBytesFromIndex(raw, 11 + isNotRoot, dataLength);
                this.raw = Utils.readBytesFromIndex(raw, 11 + isNotRoot + dataLength, (raw.length() / 2) - (11 + isNotRoot + dataLength));
            }
            default -> this.raw = Utils.readBytesFromIndex(raw, 3 + isNotRoot, (raw.length() / 2) - (3 + isNotRoot));
        }
    }

    public String getAdditionalRecordName() {
        return additionalRecordName;
    }

    public int getAdditionalRecordType() {
        return additionalRecordType;
    }

    public int getPayloadSize() {
        return payloadSize;
    }

    public int getHigherBitExtendedRCODE() {
        return higherBitExtendedRCODE;
    }

    public int getEDNS0Version() {
        return EDNS0Version;
    }

    public int getZ() {
        return z;
    }

    public int getDataLength() {
        return dataLength;
    }

    public String getData() {
        return data;
    }

    public String getRaw() {
        return raw;
    }

    public int getAdditonalRecordClass() {
        return additonalRecordClass;
    }

    public long getTtl() {
        return ttl;
    }
}
