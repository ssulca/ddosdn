package org.gstesis.mitigation.app.alert;


/**
 * Clase Timeval. Campo de la clase Alertpkt, la cual representa la estructura
 * de la alerta. guarda los valores en variables de 32 bits pero, al leerlas
 * necesita de un long para leer el dato correcto. al tratarse de un numero
 * unsigned.
 */
public class Timeval {

    private int tvSec; // Tiempo e.
    private int tvUsec;

    public Timeval() {
        this.tvSec  = 0; // seconds
        this.tvUsec = 0; // microseconds
    }

    public long getTvSec() {

        return tvSec & 0xffffffffL; // mascara del valor en 64 bits.
    }

    public void setTvSec(int tvSec) {
        this.tvSec = tvSec;
    }

    public long getTvUsec() {
        return tvUsec & 0xffffffffL; // mascara del valor en 64 bits.
    }

    public void setTvUsec(int tvUsec) {
        this.tvUsec = tvUsec;
    }
}
