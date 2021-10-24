package rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dhcp.options;

import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.dhcp.DHCPOptionsCode;
import utils.Utils;

import java.util.LinkedList;
import java.util.List;

public class ParameterRequestList implements OptionInterface {

    private final List<DHCPOptionsCode> messageTypeList;

    public ParameterRequestList(String data, int length) {
        this.messageTypeList = new LinkedList<>();
        for (int i = 0; i < length; i++) {
            this.messageTypeList.add(DHCPOptionsCode.findDhcpOptionsCode(Utils.hexStringToInt(Utils.readBytesFromIndex(data, i, 1))));
        }
    }

    public List<DHCPOptionsCode> getMessageTypeList() {
        return messageTypeList;
    }
}
