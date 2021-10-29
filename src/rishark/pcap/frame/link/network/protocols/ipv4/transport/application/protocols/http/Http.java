package rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.http;

import rishark.pcap.frame.link.network.Protocol;
import rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.ApplicationProtocol;
import utils.Utils;

import java.util.Arrays;
import java.util.List;

public class Http implements ApplicationProtocol {

    private String verb;
    private String path;
    private String version;

    private final String data;
    private final String raw;
    private final Protocol overProtocol;

    public Http(String raw, Protocol overProtocol) {
        List<String> dataList = Arrays.asList(Utils.hexStringToString(Utils.readBytesFromIndex(raw, 0, raw.length()/2)).split(" "));
        if (httpVerbs.findHttpVerb(dataList.get(0).toLowerCase()) != null)
            this.verb = dataList.get(0);
        if (dataList.get(1).contains("/"))
            this.path = dataList.get(1);
        if (dataList.get(2).contains("HTTP/"))
            this.version = dataList.get(2).split("\n")[0];

        if (this.verb != null && this.path != null && this.version != null)
            this.data = Utils.hexStringToString(Utils.readBytesFromIndex(raw, (this.verb.length() + this.path.length() + this.version.length() + 1), raw.length() / 2 - (this.verb.length() + this.path.length() + this.version.length() + 1)));
        else
            this.data = Utils.hexStringToString(Utils.readBytesFromIndex(raw, 0, raw.length()/2)); //TODO: edit later
        this.overProtocol = overProtocol;
        this.raw = Utils.readBytesFromIndex(raw, raw.length()/2, 0);
    }


    @Override
    public String getRaw() {
        return raw;
    }

    @Override
    public Protocol getOverProtocol() {
        return overProtocol;
    }

    public String getData() {
        return data;
    }

    public String getVerb() {
        return verb;
    }

    public String getPath() {
        return path;
    }

    public String getVersion() {
        return version;
    }
}
