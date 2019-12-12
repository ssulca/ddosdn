package org.gstesis.mitigation.app.alert;


/**
 * Clase Event. Campo de la clase Alertpkt, la cual representa la estructura de
 * la alerta.
 */
public class Event
{
    private int sigGen;         // Que regla  de snort genero la alerta.
    private int sigId;          // Sig ID (sid) para este generador.
    private int sigRev;         // Sig Revision para este ID.
    private int classification; // Clasificacion del evento.
    private int priority;       // Prioridad del evento.
    private int eventId;        // Event ID.
    private int eventReference; // Referencia a otros eventos, como por ejemplo,
                                // paquetes tagged.

    private Timeval refTime;    // Referencia de tiempo para la eventReference.

    public Event() {
        this.refTime = new Timeval ();
    }

    public long getSigGen()
    {
        return sigGen & 0xffffffffL;
    }

    public void setSigGen(int sigGen)
    {
        this.sigGen = sigGen;
    }

    public long getSigId() {
        return sigId & 0xffffffffL;
    }

    public void setSigId(int sigId) {
        this.sigId = sigId;
    }

    public long getSigRev() {
        return sigRev & 0xffffffffL;
    }

    public void setSigRev(int sigRev) {
        this.sigRev = sigRev;
    }

    public long getClassification() {
        return classification & 0xffffffffL;
    }

    public void setClassification(int classification) {
        this.classification = classification;
    }

    public long getPriority() {
        return priority & 0xffffffffL;
    }

    public void setPriority(int priority) {
        this.priority = priority;
    }

    public long getEventId() {
        return eventId & 0xffffffffL;
    }

    public void setEventId(int eventId) {
        this.eventId = eventId;
    }

    public long getEventReference() {
        return eventReference & 0xffffffffL;
    }

    public void setEventReference(int eventReference) {
        this.eventReference = eventReference;
    }

    public Timeval getRefTime() {
        return refTime;
    }
    public void setRefTime(Timeval refTime) {
        this.refTime = refTime;
    }
}
