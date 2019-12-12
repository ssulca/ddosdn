package org.gstesis.mitigation.app.alert;

import org.onlab.packet.*;


/**
 * Clase PackageBin. Contiene el contenido binario del paquete transmitido, que
 * intercepto el IDS y que produjo la alerta.
 */
public class PackageBin {

    private static final int IP_V4 = 0x0800;
    private static final int ICMP  = 0x01;
    private static final int TCP   = 0x06;
    private static final int UDP   = 0x11;

    private Ethernet ethernet;
    private IPv4     iPv4;
    private ICMP     icmp;
    private TCP      tcp;
    private UDP      udp;

    /**
     * Contructor
     */
    public PackageBin(){}

    public String getSourceIP() {
        //return sourceIP;
        return IPv4.fromIPv4Address(iPv4.getSourceAddress());
    }
    public String getDstIP(){
        return IPv4.fromIPv4Address(iPv4.getDestinationAddress());
    }

    /**
     * Metodo setFields. Llama a funciones que realizan el llenado por capa de
     * comunicacion (transporte, red, aplicacion, etc.) de los campos de la
     * estructura de la alerta.
     * @param arreglo byte[] Contiene el contenido binario del paquete
     *                transmitido que produjo la alerta.
     */
    public void setFields (byte[] arreglo) {
        ethernet = new Ethernet();
        setEthernet(arreglo);
        //setFieldsEthernet(arreglo);
        if(ethernet.getEtherType() == IP_V4) {
            //setFieldsIP (arreglo);
            setIPv4(arreglo);

            switch (iPv4.getProtocol()){
                case TCP:
                    setTcp(arreglo);
                    break;
                case UDP:
                    setUdp(arreglo);
                    break;
                case ICMP:
                    setIcmp(arreglo);
                    break;
            }
        }
    }

    /**
     * set Ethernet object
     * @param pkt byte [] pkt form snort alert
     */
    private void setEthernet(byte[] pkt){
        byte [] bytes = new byte[6];

        System.arraycopy(pkt,0, bytes,0,6);
        ethernet.setDestinationMACAddress(bytes);
        System.arraycopy(pkt,6, bytes,0,6);
        ethernet.setSourceMACAddress(bytes);
        ethernet.setEtherType((short)((pkt[12] & 0xff) << 8 | (pkt[13] & 0xff)));
    }

    /**
     * set IP Object
     * @param pkt byte [] pkt form snort alert
     */
    private void setIPv4(byte[] pkt){
        iPv4 = new IPv4();

        iPv4.setVersion  (pkt[14]);
        iPv4.setDiffServ (pkt[15]); //IPv4 se utiliza Tos 6 bits DSCP y 2 bits ECN

        iPv4.setIdentification((short)((pkt[18] & 0xff) << 8 | (pkt[19] & 0xff)));
        iPv4.setFlags(pkt[20]);
        iPv4.setFragmentOffset((short)((pkt[20] & 0xff) << 8 | (pkt[21] & 0xff)));
        iPv4.setTtl(pkt[22]);
        iPv4.setProtocol(pkt[23]);
        iPv4.setChecksum((short)((pkt[24] & 0xff)<<8 | (pkt[25] & 0xff)));
        iPv4.setSourceAddress((pkt[26] & 0xff)<<24 |
                (pkt[27] & 0xff)<<16 | (pkt[28] & 0xff)<<8 | (pkt[29] & 0xff));
        iPv4.setDestinationAddress((pkt[30] & 0xff)<<24 |
                (pkt[31] & 0xff)<<16 | (pkt[32] & 0xff)<<8 | (pkt[33] & 0xff));
    }

    /**
     * get Ethernet Object
     * @return ehternet object or null
     */
    public  Ethernet getEthernet(){
        return ethernet;
    }

    /**
     * get IPv4 Object
     * @return ipv4 object or null
     */
    public IPv4 getiPv4(){
        return iPv4;
    }

    /**
     * get src Mac
     * @return String src MAC
     */
    public String getSourceMac(){
        //return sourceMac;
        return ethernet.getSourceMAC().toString();
    }

    /**
     * set icmp object
     * @param pkt byte [] bytes pkt
     */
    private void setIcmp (byte [] pkt) {
        icmp = new ICMP();
        icmp.setIcmpType(pkt[34]);
        icmp.setIcmpCode(pkt[35]);
        icmp.setChecksum((short)((pkt[36] & 0xff)<<8 | (pkt[37] & 0xff)));
    }

    /**
     * set udp oject
     * @param pkt byte [] pkt alet msg
     */
    private void setUdp(byte[] pkt){
        udp = new UDP();
        udp.setSourcePort((pkt[34] & 0xff) << 8 | (pkt[35] & 0xff));
        udp.setDestinationPort((pkt[36] & 0xff) << 8 | (pkt[37] & 0xff));
        udp.setChecksum((short)((pkt[40] & 0xff) << 8 | (pkt[41] & 0xff)));
    }

    /**
     * set TCP header object
     * @param pkt byte [] contains heder
     */
    private void setTcp ( byte [] pkt) {
        tcp = new TCP();
        tcp.setSourcePort((pkt[34] & 0xff)<<8 | (pkt[35] & 0xff));
        tcp.setDestinationPort((pkt[36] & 0xff)<<8 | (pkt[37] & 0xff));
        tcp.setSequence((pkt[38] & 0xff)<<24 |
                (pkt[39] & 0xff)<<16 | (pkt[40] & 0xff)<<8 | (pkt[41] & 0xff));
        tcp.setAcknowledge((pkt[42] & 0xff)<<24 |
                (pkt[43] & 0xff)<<16 | (pkt[44] & 0xff)<<8 | (pkt[45] & 0xff));
        tcp.setFlags((short)((pkt[46] & 0xff)<<8 | (pkt[47] & 0xff)));
        tcp.setWindowSize((short)((pkt[48] & 0xff)<<8 | (pkt[49] & 0xff)));
        tcp.setChecksum((short)((pkt[50] & 0xff)<<8 | (pkt[51] & 0xff)));
        tcp.setUrgentPointer((short)((pkt[52] & 0xff)<<8 | (pkt[53] & 0xff)));
    }

    /**
     * get TCP object
     * @return tcp object or null
     */
    public TCP getTcp(){
        return tcp;
    }
    /**
     * get UDP pkt object
     * @return udp object or null
     */
    public UDP getUdp(){
        return udp;
    }
}




/*

PKT:
    Capa Ethernet.
        Destination. 6 bytes.
        Source. 6 bytes.
        Type.  (0x800). 2 bytes.

    Capa de red.
        69. Version and header length (0101). 1 byte.
        00  Servicios diferenciados. 1 byte.
        00 84   Total lenght. 2 bytes.
        Identificacion. 1 byte.
        Flags. 1 byte
        fragmentOffset.2 bytes.
        TimeToLive. 1
        Protocol. 1
        Header checksum. 2 bytes.
        Source and destination. 8 bytes.
        Text item. 4 bytes.
     ICMP
        Type. 8
        Code. 0
        Checksum (2 bytes).
     Capa de transporte.
        No hay.





 */
