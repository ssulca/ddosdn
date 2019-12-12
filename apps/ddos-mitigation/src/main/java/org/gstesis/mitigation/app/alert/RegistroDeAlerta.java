package org.gstesis.mitigation.app.alert;

public class RegistroDeAlerta {

    private String message;
    private String sourceIP;
    private String destIP;
    private long   sigGen;
    private long   sigID;

    public RegistroDeAlerta (){
        this.message  = "";
        this.destIP   = "";
        this.sourceIP = "";
        this.sigGen   = 0;
        this.sigID    = 0;
    }

    public RegistroDeAlerta (String message, String sourceIP, String destIP,
                             long sigGen, long sigID){
        this.message  = message;
        this.destIP   = destIP;
        this.sourceIP = sourceIP;
        this.sigGen   = sigGen;
        this.sigID    = sigID;
    }


    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getSourceIP() {
        return sourceIP;
    }

    public void setSourceIP(String sourceIP) {
        this.sourceIP = sourceIP;
    }

    public String getDestIP() {
        return destIP;
    }

    public void setDestIP(String destIP) {
        this.destIP = destIP;
    }

    public long getSigGen() {
        return sigGen;
    }

    public void setSigGen(long sigGen) {
        this.sigGen = sigGen;
    }

    public long getSigID() {
        return sigID;
    }

    public void setSigID(long sigID) {
        this.sigID = sigID;
    }


}
