package rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dhcp.options;

import utils.Utils;

public class DhcpMessageType {

    private final MessageType messageType;

    public DhcpMessageType(String data, int length) {
        this.messageType = MessageType.findMessageType(Utils.hexStringToInt(Utils.readBytesFromIndex(data, 0, length)));
    }

    public MessageType getMessageType() {
        return messageType;
    }
}
