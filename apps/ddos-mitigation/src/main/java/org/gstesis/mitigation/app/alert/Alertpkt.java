package org.gstesis.mitigation.app.alert;

import java.nio.charset.StandardCharsets;

/**
 * Clase Alertpkt.
 * @brief Contiene la estructura de la alerta enviada por el IDS Snort. this
 * struct is for the alert socket code.... FIXTHIS alert unix sock supports
 * l2-l3-l4 encapsulations
 * Snort Struct
 * <a
 * href="http://www.rajivchakravorty.com/source-code/.tmp/snort-html/struct__Alertpkt.html#o0">
 * TimSort</a>
 * @see Event
 * @see PackageBin
 * @see PcapPkthdr
 * @see Timeval
 *
 */
public class Alertpkt {

    private static final int ALERTMSG_LENGTH = 256;
    private static final int SNAPLEN = 65535; //= 1514; // 65535 en snort 2.11

    private byte[] alertMsg; // 256 bytes.
    private PcapPkthdr pkth; // 16 bytes.
    private int dlthdr;      // 4 bytes.Datalink header offset. (Ethernet, etc.).
    private int nethdr;      // 4 bytes.Network header offset. (IP, etc.).
    private int transhdr;    // 4 bytes.Transport header offset (TCP/UDP/ICMP, etc.).
    private int data;        // 4 bytes.Data offset.
    private int val;         // 4 bytes.Campos que son validos.
    private byte[] pkt;      // 1514 bytes #define //Bytes del paquete.
    private Event event;     // 36 bytes.

    private PackageBin packageBin; // Contenido del paquete (formato tcpdump).

    public Alertpkt() {
        this.alertMsg   = new byte [ALERTMSG_LENGTH];
        this.pkth       = new PcapPkthdr();
        this.pkt        = new byte[SNAPLEN];
        this.event      = new Event();
        this.packageBin = new PackageBin();
    }

    /**
     * get del mensaje de alerMsg del pakete de alerta de snort,
     * @return String mensaje codificado en utf-8
     */
    public String getAlertMsg() {
        try{
            // remplaza todos los 0x00 del arrelgo con "" para lectura de un
            // String en JAVA 
            return (new String(this.alertMsg, StandardCharsets.UTF_8)).replaceAll("\0", "");
        }
        catch (Exception e) {
            e.printStackTrace ();
            return "Cadena de error en getAlertMsg.";
        }
    }

    /**
     * set alert mensaje TODO: controlar el size del arreglo del bytes.
     * @param alertMsg bytes []
     */
    public void setAlertMsg(byte[] alertMsg) {
        this.alertMsg = alertMsg;
    }

    /**
     * retorna el header del paquete
     * @return PcapPkthdr
     */
    public PcapPkthdr getPkth() {
        return pkth;
    }

    /**
     * set Pkth header,ok.
     * @param seconds int,
     * @param microseconds int,
     * @param caplen int,
     * @param len int,
     */
    public void setPkth(int seconds, int microseconds, int caplen, int len) {
        this.pkth.setTs(seconds, microseconds);
        this.pkth.setCaplen(caplen);
        this.pkth.setLen(len);
    }

    public long getDlthdr() {
        return dlthdr & 0xffffffffL;
    }

    public void setDlthdr(int dlthdr) {
        this.dlthdr = dlthdr;
    }

    public long getNethdr() {
        return nethdr & 0xffffffffL;
    }

    public void setNethdr(int nethdr) {
        this.nethdr = nethdr;
    }

    public long getTranshdr() {
        return transhdr & 0xffffffffL;
    }

    public void setTranshdr(int transhdr) {
        this.transhdr = transhdr;
    }

    public long getData() {
        return data & 0xffffffffL;
    }

    public void setData(int data) {
        this.data = data;
    }

    public long getVal() {
        return val & 0xffffffffL;
    }

    public void setVal(int val) {
        this.val = val;
    }

    /**
     *  retorna el arreglo de bytes del paquete NET formato Ethernet y demas
     *  cabeceras
     * @return byte[]
     */
    public byte[] getPkt() {
        return pkt;
    }

    /**
     * set paquete NET y set clase packbin para lectura de los headers del
     * paquete, tales como Ethernet, Ip , ICMP, TCP , UDP, etc.
     * @param pkt byte[] arreglo de bytes del paqute NET
     */
    public void setPkt(byte[] pkt) {
        this.pkt = pkt;
        this.packageBin.setFields(pkt);
    }

    public Event getEvent() {
        return event;
    }

    /**
     * set Event al final de la estructura de Snort propias para identificar las
     * Reglas -> Match con snort
     * @param arreglo int[]
     */
    public void setEvent(int[] arreglo) {
        if (arreglo.length > 0) {
            this.event.setSigGen              (arreglo[0]);
            this.event.setSigId               (arreglo[1]);
            this.event.setSigRev              (arreglo[2]);
            this.event.setClassification      (arreglo[3]);
            this.event.setPriority            (arreglo[4]);
            this.event.setEventId             (arreglo[5]);
            this.event.setEventReference      (arreglo[6]);
            this.event.getRefTime().setTvSec  (arreglo[7]);
            this.event.getRefTime().setTvUsec (arreglo[8]);

        }
    }

    /**
     * class contains los headers del paquete NET
     * @return PackageBin
     */
    public PackageBin getPackageBin() {
        return packageBin;
    }

    /**
     * Return String format segun RF 17
     * @return
     */
    @Override
    public String toString(){

        String toString = "["+event.getSigId()+"] "+ getAlertMsg()+" "+
                getPackageBin().getSourceIP()+" -> "+getPackageBin().getDstIP();
        return toString;
    }
}




