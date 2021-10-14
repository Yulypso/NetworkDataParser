package rishark.pcap.frame.link.network.protocols.ipv4.transport.application.protocols.ftp;

public enum FTPCommand {

    ABOR("ABOR"),
    ACCT("ACCT"),
    ADAT("ADAT"),
    ALLO("ALLO"),
    APPE("APPE"),
    AUTH("AUTH"),
    CCC("CCC"),
    CDUP("CDUP"),
    CONF("CONF"),
    CWD("CWD"),
    DELE("DELE"),
    ENC("ENC"),
    EPRT("EPRT"),
    EPSV("EPSV"),
    FEAT("FEAT"),
    HELP("HELP"),
    LANG("LANG"),
    LIST("LIST"),
    LPRT("LPRT"),
    LPSV("LPSV"),
    MDTM("MDTM"),
    MIC("MIC"),
    MKD("MKD"),
    MLSD("MLSD"),
    MLST("MLST"),
    MODE("MODE"),
    NLST("NLST"),
    NOOP("NOOP"),
    OPTS("OPTS"),
    PASS("PASS"),
    PASV("PASV"),
    PBSZ("PBSZ"),
    PORT("PORT"),
    PROT("PROT"),
    PWD("PWD"),
    QUIT("QUIT"),
    REIN("REIN"),
    REST("REST"),
    RETR("RETR"),
    RMD("RMD"),
    RNFR("RNFR"),
    RNTO("RNTO"),
    SITE("SITE"),
    SIZE("SIZE"),
    SMNT("SMNT"),
    STAT("STAT"),
    STOR("STOR"),
    STOU("STOU"),
    STRU("STRU"),
    SYST("SYST"),
    TYPE("TYPE"),
    USER("USER"),
    XCUP("XCUP"),
    XMKD("XMKD"),
    XPWD("XPWD"),
    XRCP("XRCP"),
    XRMD("XRMD"),
    XRSQ("XRSQ"),
    XSEM("XSEM"),
    XSEN("XSEN");

    private final String ftpCommand;

    FTPCommand(String ftpCommand) {
        this.ftpCommand = ftpCommand;
    }

    public static FTPCommand findFtpCommand(String s){
        for(FTPCommand p : FTPCommand.values()) {
            if(p.getFtpCommand().equals(s)) {
                return p;
            }
        }
        return null;
    }

    public String getFtpCommand() {
        return ftpCommand;
    }
}
