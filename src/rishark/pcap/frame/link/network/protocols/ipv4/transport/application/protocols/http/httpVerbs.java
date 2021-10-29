package rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.http;

public enum httpVerbs {

    GET("get"),
    HEAD("head"),
    POST("post"),
    PUT("put"),
    DELETE("delete"),
    CONNECT("connect"),
    OPTIONS("options"),
    TRACE("trace"),
    PATCH("patch");

    private final String httpVerb;

    httpVerbs(String httpVerb) {
        this.httpVerb = httpVerb;
    }

    public static httpVerbs findHttpVerb (String s){
        for(httpVerbs p : httpVerbs.values()) {
            if(p.getHttpVerb().equals(s)) {
                return p;
            }
        }
        return null;
    }

    public String getHttpVerb() {
        return httpVerb;
    }
}
