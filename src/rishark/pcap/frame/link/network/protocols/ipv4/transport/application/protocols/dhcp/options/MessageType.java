package rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dhcp.options;

import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dhcp.DHCPOptionsCode;

public enum MessageType {

    Discover(1),
    Offer(2),
    Request(3),
    Decline(4),
    Ack(5),
    Nak(6),
    Release(7);

    private final int messageType;

    MessageType(int messageType) {
        this.messageType = messageType;
    }

    public static MessageType findMessageType(int i){
        for(MessageType oc : MessageType.values()) {
            if(oc.getMessageType() == i) {
                return oc;
            }
        }
        return null;
    }

    public int getMessageType() {
        return messageType;
    }
}
