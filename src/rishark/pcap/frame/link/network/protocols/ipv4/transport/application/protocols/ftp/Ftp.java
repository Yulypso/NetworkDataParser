package rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.ftp;

import rishark.pcap.frame.link.network.Protocol;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.ApplicationProtocol;
import utils.Utils;

import java.util.Arrays;
import java.util.List;

public class Ftp implements ApplicationProtocol {

    private FTPCode responseCode;
    private FTPCommand requestCommand;
    private String arguments;

    private final String raw;
    private final Protocol overProtocol;

    public Ftp(String raw, Protocol overProtocol) {
        List<String> dataList = Arrays.asList(Utils.hexStringToString(Utils.readBytesFromIndex(raw, 0, raw.length()/2)).trim().split(" "));

        try {
            this.responseCode = FTPCode.findFtpCode(Integer.parseInt(dataList.get(0).trim()));
            this.arguments = Utils.hexStringToString(Utils.readBytesFromIndex(raw, dataList.get(0).trim().length() + 1,raw.length()/2 - (dataList.get(0).trim().length() + 1)));
        } catch (Exception e) {
            this.requestCommand = FTPCommand.findFtpCommand(dataList.get(0).toUpperCase().trim());
            assert this.requestCommand != null;
            this.arguments = Utils.hexStringToString(Utils.readBytesFromIndex(raw, this.requestCommand.toString().length() + 1, raw.length()/2 - (this.requestCommand.toString().length() + 1)));
        } finally {
            if (this.requestCommand != null)
                this.raw = Utils.hexStringToString(Utils.readBytesFromIndex(raw,this.requestCommand.toString().length() + 1 + this.arguments.length(), raw.length()/2 - (this.requestCommand.toString().length() + 1 + this.arguments.length())));
            else if (this.responseCode != null)
                this.raw = Utils.hexStringToString(Utils.readBytesFromIndex(raw,dataList.get(0).trim().length() + 1 + this.arguments.length(), raw.length()/2 - (dataList.get(0).trim().length() + 1 + this.arguments.length())));
            else
                this.raw = raw;
        }
        this.overProtocol = overProtocol;
    }

    @Override
    public String getRaw() {
        return raw;
    }

    @Override
    public Protocol getOverProtocol() {
        return this.overProtocol;
    }

    public FTPCode getResponseCode() {
        return responseCode;
    }

    public FTPCommand getRequestCommand() {
        return requestCommand;
    }

    public String getArguments() {
        return arguments;
    }
}
