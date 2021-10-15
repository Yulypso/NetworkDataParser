package rishark.pcap.frame.link.network.protocols.ipv4.transport.application;

public enum AppProtocol {

    FTP("ftp"),
    DNS("dns");

    private final String appProtocol;

    AppProtocol(String appProtocol) {
        this.appProtocol = appProtocol;
    }

    public static AppProtocol findProtocol(String s){
        for(AppProtocol p : AppProtocol.values()) {
            if(p.getProtocol().equals(s)) {
                return p;
            }
        }
        return null;
    }

    public String getProtocol() {
        return appProtocol;
    }
}
