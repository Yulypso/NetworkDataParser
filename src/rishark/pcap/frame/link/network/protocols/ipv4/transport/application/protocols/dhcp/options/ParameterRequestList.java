package rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dhcp.options;

import utils.Utils;

import java.util.LinkedList;
import java.util.List;

public class ParameterRequestList {

    private final List<MessageType> messageTypeList;

    public ParameterRequestList(String data, int length) {
        System.out.println(data);
        this.messageTypeList = new LinkedList<>();
        for (int i = 0; i < length; i++) {
            this.messageTypeList.add(MessageType.findMessageType(Utils.hexStringToInt(Utils.readBytesFromIndex(data, i, 1))));
        }
    }

    public List<MessageType> getMessageTypeList() {
        return messageTypeList;
    }
}
