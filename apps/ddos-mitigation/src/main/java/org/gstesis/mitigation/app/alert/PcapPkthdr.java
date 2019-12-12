package org.gstesis.mitigation.app.alert;

/**
 * Clase PcapPkthdr. Campo de la clase Alertpkt, la cual representa la
 * estructura de la alerta.
 */
public class PcapPkthdr
{
    private Timeval ts;     // Timestamps de capturas.
    private int     caplen; // Número de bytes capturados actualmente.
    private int     len;    // Número de bytes reales en el paquete.

    public PcapPkthdr() {
        this.ts = new Timeval ();
    }

    public Timeval getTs() {
        return ts;
    }

    public void setTs(int seconds, int microseconds) {
        this.ts.setTvSec  (seconds);
        this.ts.setTvUsec (microseconds);
    }

    public long getCaplen() {
        return this.caplen & 0xffffffffL;
    }

    public void setCaplen(int caplen) {
        this.caplen = caplen;
    }

    public long getLen() {
        return this.len & 0xffffffffL;
    }

    public void setLen(int len) {
        this.len = len;
    }
}
