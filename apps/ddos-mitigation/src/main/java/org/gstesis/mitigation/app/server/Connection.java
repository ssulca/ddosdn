package org.gstesis.mitigation.app.server;

import org.onlab.packet.IpAddress;
import org.onosproject.net.DeviceId;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.net.InetSocketAddress;
import java.net.Socket;

import org.gstesis.mitigation.app.AppError;
import org.gstesis.mitigation.app.alert.Alertpkt;
import org.gstesis.mitigation.app.alert.RegistroDeAlerta;
import org.gstesis.mitigation.app.firewall.AttackType;
import org.gstesis.mitigation.app.firewall.Firewall;

import org.slf4j.Logger;
import static java.lang.Thread.sleep;
import static org.slf4j.LoggerFactory.getLogger;

/**
 * Clase Connection. Runnable Esta clase efectúa el procesamiento de la alerta
 * recibida de Snort y llama al firewall.
 * @see java.lang.Runnable
 * @see Alertpkt
 */
public class Connection  implements Runnable {

    private static final String MESG_OK = "OK";
    private static final String MESG_FAIL = "NO";
    //private static final int buffersize = 65864;//65863;
    private static final String ALERT_FORMAT = "\nFw: [{}:{}] {} [*] {} -> {}";
    private static final int ALERTMSG_LENGTH = 256;
    private static final int PCAP_SNAPLEN    = 65536;
    private static final int TIME_SLEEP      = 500;
    // Logger Client
    private final Logger log = getLogger(getClass());

    //////////////////////////// OUR variables /////////////////////////////
    private Socket                    clientSocket;
    private Firewall                  firewall;
    // Lista donde se almacenaran todas las alertas de un IDS.
    private HashSet<RegistroDeAlerta> listaDeAlertas;
    // Lista de SID de las alertas que puede reconocer el ONOS del IDS.
    private ArrayList<Long>           sidsIDS;

    /**
     * Constructor de la Clase Connection
     * @param clientSocket Socket TCP
     */
    public Connection(Socket clientSocket, Firewall firewall, ArrayList<Long> sidsIDS,
                      HashSet<RegistroDeAlerta> listaDeAlertas) {

        this.clientSocket   = clientSocket;
        this.firewall       = firewall;
        this.listaDeAlertas = listaDeAlertas;
        this.sidsIDS        = sidsIDS;
    }

    /**
     * @deprecated
     * Constructor para test
     */
    public Connection(ArrayList<Long> sidsIDS, HashSet<RegistroDeAlerta> listaDeAlertas){
        this.clientSocket   = null;
        this.firewall       = null;
        this.listaDeAlertas = listaDeAlertas;
        this.sidsIDS        = sidsIDS;
    }


    /**
     * Metodo run. Efectúa el procesamiento de la alerta recibida y llama al
     * firewall.
     */
    @Override
    public void run() {

        DataInputStream dataInputSock;
        PrintWriter     dataOutputSock;
        Alertpkt        alertMessage;

        AttackType      attackType;
        Set<DeviceId>   deviceIdSet;   // Devices where are written rules

        String          ipCliSocket;
        IpAddress       ipTopoNet;
        String          description;
        // Timeout de la conexion
        // int MAX_SLEEP_COUNT = 100;
        // Para leer lo que envía cliente.
        try {
            // Ahora lee de manera completa buffersize
            dataInputSock  = new DataInputStream(clientSocket.getInputStream());
            dataOutputSock = new PrintWriter(clientSocket.getOutputStream(), true);
            // Get Ip Client
            ipCliSocket = ((InetSocketAddress) clientSocket.getRemoteSocketAddress())
                    .getAddress().toString();

            if(clientSocket.isClosed()) {
                log.error("Socket cliente cerrado.");
            }

            log.info("::::Authentication::::");
            ///////////////////////// AUTHENTICATION //////////////////////////////
            ipTopoNet = authenticateHandShake(dataInputSock);

            if(ipTopoNet == null){
                log.error("Authentication Fail");
                dataOutputSock.println(MESG_FAIL);
                dataInputSock.close();  // Cierro buffer.
                dataOutputSock.close(); // Cierro buffer.
                clientSocket.close();
                return;
            }
            else {
                log.info("Authentication Success Ip: {}", ipTopoNet.toString());
                dataOutputSock.write(MESG_OK);
            }

            log.info("::::Ready to Read Alerts::::");
            ///////////////////////// READ ALERTS //////////////////////////////
            while (!Thread.currentThread().isInterrupted() && clientSocket.isConnected() &&
                    !clientSocket.isClosed()){
                while (dataInputSock.available() <= 0) {
                    sleep(TIME_SLEEP);
                    // Chequeo de error o sobrepasó timeout.
                    if (dataOutputSock.checkError()) {
                        log.info("SocketListener: server and socket connect is lost...");
                        dataInputSock.close();   // Cierro buffer.
                        dataOutputSock.close();  // Cierro buffer.
                        clientSocket.close();    // Cierro socket cliente.
                        clientSocket = null;
                        return;
                    } // if
                } // while (dataInputSock.available() <= 0)

                log.info("Msg recived from {}", ipCliSocket);
                // Leer y procesar resultado.
                alertMessage = recognizeAlert(dataInputSock);
                if(alertMessage != null) {

                    registerAlert(alertMessage); // Registro de Alerta
                    // Proceso si es un ataque.
                    attackType = firewall.isAttack(
                            alertMessage.getEvent().getSigId(),
                            alertMessage.getPackageBin().getSourceIP());

                    switch (attackType){
                        case FLOOD: // Ataque a los servidores. No incluye smurf attack.
                            // Encuentro los OVS mas cercanos a la IP del host atacante.
                            deviceIdSet = firewall.findSwitchConnectedToHost(
                                    alertMessage.getPackageBin().getSourceIP());
                            // Set en dichos OVS las reglas de drop correspondientes.
                            description  = "["+ AttackType.FLOOD+":"+
                                    ipTopoNet.getIp4Address()+"] "+alertMessage.toString();
                            firewall.defAttack(deviceIdSet, alertMessage, description);
                            break;
                        case SMURF: // Smurf Attack to servers.
                            // Encuentro todos los OVS de la red.
                            deviceIdSet = firewall.getAllSwitch();
                            // Set en todos los OVS las reglas de drop correspondientes.
                            description  = "["+ AttackType.SMURF+":"+
                                    ipTopoNet.getIp4Address()+"] "+alertMessage.toString();

                            firewall.defSmurfAttack(
                                    deviceIdSet, alertMessage.getPackageBin().getSourceIP(),
                                    alertMessage.getPackageBin().getDstIP(), description);
                            break;
                        case NO_RECOGNISED:
                            log.info("Alert: {}", AttackType.NO_RECOGNISED.toString());
                        default:
                            break;
                    }

                    log.info(ALERT_FORMAT, alertMessage.getEvent().getSigGen(),
                            alertMessage.getEvent().getSigId(),
                            alertMessage.getAlertMsg(),
                            alertMessage.getPackageBin().getSourceIP(),
                            alertMessage.getPackageBin().getDstIP());
                }
                else{
                    log.error("Connection: Error read Alertpkt or Invalid Message from IDS.");
                }
            }//while (!Thread.currentThread().isInterrupted())
        }
        catch (IOException e) {
            log.error ("{}, ClieteSocket create error I/O, ", AppError.NO_SUCH);
            return;
        }
        catch (Exception e){
            log.error("{}, SocketListener: Exception = {}", AppError.UNKNOWN, e.toString());
            try{

                clientSocket.close(); //Cierro socket cliente.
            }
            catch (IOException exp) {
                log.error("{} SocketListener: Exception close socket ", AppError.NO_SUCH);
            }
            clientSocket = null;
            return;
        }

        try {
            if (clientSocket != null) {
                dataInputSock.close();  // Cierro buffer.
                dataOutputSock.close(); // Cierro buffer.
                clientSocket.close();
                clientSocket = null;
                log.info("SocketListener: stop(): Client Socket close() is done...");
            }
        }
        catch (IOException e) {
            log.error ("{} stop(): Server Socket closing error", AppError.NO_SUCH);
        }
    }

    /**
     * Authentication Handshake
     * @param inputStream, input
     * @return ip adress
     */
    private  IpAddress authenticateHandShake(DataInputStream inputStream){

        final String regex = "[\"ips\":\"{}\\[\\]]";

        int            size;
        byte[]         msg;
        Set<String>    ipsIdsSet;
        Set<IpAddress> expectedIpsIds;
        String         s;

        ipsIdsSet      = new HashSet<>();
        expectedIpsIds = IdsResources.getInstance().getIpAddressSet();
        try{
            do {
                size = inputStream.available(); // bloking
            }while (size <= 0);

            msg  = new byte[size];
            inputStream.readFully(msg); // MAX 128 BYTES (Characters)

            s = new String(msg);
            // System.out.println(s);
            s = s.replaceAll(regex, "");
            // System.out.println(s);
            ipsIdsSet.addAll(Arrays.asList(s.split(",")));
            for (String ipAddress : ipsIdsSet) {
                for (IpAddress ipExp : expectedIpsIds) {
                    if (ipExp.getIp4Address().toString().equals(ipAddress.trim()))
                        return ipExp;
                }
            }
            return null;
        }
        catch (IOException e){
            log.error("{}", AppError.INVALID);
            e.printStackTrace();
            return null;
        }

    }

    /**
     * Metodo para armar la estructura de la alerta de snort.
     * @param input DataInputStream, buufer en donde se recibio la alerta
     * @return Alertpkt alerta completa si se llenaron los datos o null en caso
     * contrario.
     */
    public Alertpkt recognizeAlert(DataInputStream input){
        Alertpkt alert;
        byte[]   msg ;
        int[]    intArray ;

        alert = null;
        try {
            if (input.available() > 0){
                // Mensaje de la alerta.
                msg = new byte[ALERTMSG_LENGTH];
                input.readFully(msg);

                alert = new Alertpkt();
                alert.setAlertMsg(msg);

                msg      = new byte[4];
                intArray = new int[9];
                for (int i = 0; i < 9; i++) {
                    input.readFully(msg);
                    intArray[i] = readInt(msg);
                }

                // Struct PcapPkthdr.
                alert.setPkth(intArray[0], intArray[1], intArray[2],intArray[3]);

                alert.setDlthdr(intArray[4]);   // u_int32_t dlthdr
                alert.setNethdr(intArray[5]);   // u_int32_t nethdr
                alert.setTranshdr(intArray[6]); // u_int32_t transhdr
                alert.setData(intArray[7]);     // u_int32_t data
                alert.setVal(intArray[8]);      // u_int32_t val

                //Package alert (Pkt).
                msg = new byte[PCAP_SNAPLEN]; // 90
                input.readFully(msg);
                alert.setPkt(msg);

                //Event.
                msg = new byte[4];
                intArray = new int[9];
                for (int i = 0; i < 8; i++){
                    input.readFully(msg);
                    intArray[i] = readInt(msg);
                }
                //TOD:curiso comportamiento de los utlimos 3 bytes en la alerta
                msg = new byte[3];
                input.readFully(msg);
                intArray[8] = readInt(msg);
                alert.setEvent(intArray);

                if (!this.sidsIDS.contains(alert.getEvent().getSigId())) {
                    log.info("Alerta desconocida. Mensaje: {}, Sid ID: {}",
                            alert.getAlertMsg(), alert.getEvent().getSigId());
                    return null;
                }

            }
        }
        catch (Exception e){
            log.error("Connection: Exception close socket = {}", e.toString());
        }

        return alert;
    }

    /**
     * lee un array de bytes leidos desordenados
     * @param b bytes [] para convertir.
     * @return int, numero con el orden correcto.
     */
    private static int readInt(byte[] b) {
        if (b.length == 4)
            return b[3] << 24 | (b[2] & 0xff) << 16 | (b[1] & 0xff) << 8 | (b[0] & 0xff);
        else if (b.length == 3)
            return (b[2] & 0xff) << 16 | (b[1] & 0xff) << 8 | (b[0] & 0xff);

        return 0;
    }

    /**
     * Llenado de lista de alertas en caso de que la alerta no se encuentre en
     * dicha lista.
     * @param alert Reconocida
     */
    public void registerAlert(Alertpkt alert) {
        RegistroDeAlerta registro;

        registro = new RegistroDeAlerta(alert.getAlertMsg(),
                alert.getPackageBin().getSourceIP(),
                alert.getPackageBin().getDstIP(),
                alert.getEvent().getSigGen(),
                alert.getEvent().getSigId());

        synchronized (this.getClass()) {
            listaDeAlertas.add(registro);
        }
    }

    public HashSet<RegistroDeAlerta> getListaDeAlertas() {
        return listaDeAlertas;
    }
}

