package org.gstesis.mitigation.app.firewall;

import org.onosproject.incubator.net.faultmanagement.alarm.*;
import org.onosproject.net.*;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.host.HostService;
import org.onosproject.net.intent.Intent;
import org.onosproject.net.intent.IntentService;
import org.onosproject.net.intent.SinglePointToMultiPointIntent;
import org.onosproject.core.ApplicationId;

import org.onlab.packet.*;

import org.gstesis.mitigation.app.alert.Alertpkt;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import org.slf4j.Logger;
import static org.slf4j.LoggerFactory.getLogger;

/**
 * Clase Firewall. Detecta si una alerta corresponde a un ataque o no. En caso
 * de ataque: Encuentra el OVS mas cercano al host atacante. Detiene el ataque
 * colocando las correspondientes reglas en los OVS.
 */
public class Firewall {

    //private static final int PRIORITY = 128;
    // Prioridad importante para ONOS. ff
    private static final int DROP_PRIORITY = 40004;
    private static final int TIMEOUT_SEC   = 30; // rule duration (seg).
    private static final String ANNT       = "killa";
    private static final String EDGE       = "edge";

    private static Firewall ourInstance = new Firewall (); // singleton.
    private final Logger log            = getLogger(getClass()); //Logger.

    private ApplicationId        appId;
    private FlowObjectiveService flowObjectiveService;
    private DeviceService        deviceService;
    private HostService          hostService;
    private IntentService        intentService;

    private AlarmService         alarmService;
    private AlarmProviderService alarmProviderService;
    // Para seguir pings de cada dispositivo en una base de tiempo.
    private Set<RegistroRegla>   rulesList;
    // Alertas IDS.
    private ArrayList<Long>      sidsIDSToServers;

    public static Firewall getInstance() {
        return ourInstance;
    }

    /**
     * Singleton Constructor
     */
    private Firewall() {
        hostService          = null;
        flowObjectiveService = null;
        appId                = null;
        deviceService        = null;
        rulesList            = new HashSet<>();
    }

    /**
     * Metodo configFirewall. Set de la ApplicationId y del
     * FlowObjectiveService, utiles para la creacion de la regla a instalar en
     * los OVS. Set del nuevo hostService, proviene de appComponent, neserario
     * para obtener los sw conectados a un determinado host.
     * @param flowObjectiveService FlowObjectiveService Servicio para programar
     *                    reglas de flujo del plano de datos de manera
     *                    independiente de la configuración de canalización de
     *                    la tabla del dispositivo específico.
     * @param appId ApplicationId Identificador de la app.
     * @param hostService HostService Servicio host de Onos. ReferenceCardinality.MANDATORY_UNARY
     * @param alarmProviderService ONOS service ReferenceCardinality.MANDATORY_UNARY
     * @param alarmService ONOS service ReferenceCardinality.MANDATORY_UNARY
     * @param deviceService ONOS service ReferenceCardinality.MANDATORY_UNARY
     * @param intentService ONOS Service ReferenceCardinality.MANDATORY_UNARY
     *
     * @see org.onosproject.net.device.DeviceService;
     * @see org.onosproject.net.flowobjective.FlowObjectiveService;
     * @see org.onosproject.net.host.HostService;
     * @see org.onosproject.net.intent.IntentService;
     * @see org.onosproject.incubator.net.faultmanagement.alarm.AlarmProviderService
     * @see org.onosproject.incubator.net.faultmanagement.alarm.AlarmService
     *
     */
    public void configFirewall (ApplicationId appId, FlowObjectiveService flowObjectiveService,
                                HostService hostService, DeviceService deviceService,
                                IntentService intentService, AlarmService alarmService ,
                                AlarmProviderService alarmProviderService){

        this.appId                = appId;
        this.flowObjectiveService = flowObjectiveService;
        this.hostService          = hostService;
        this.deviceService        = deviceService;
        this.intentService        = intentService;
        this.alarmService         = alarmService;
        this.alarmProviderService = alarmProviderService;
        this.sidsIDSToServers     = FirewallResources.getInstance().getSidAlertsIDSToServers();
    }

    /**
     * getter
     * @return retorna la lista de reglase del FW
     */
    public Set<RegistroRegla> getRulesList() {
        return rulesList;
    }

    public ArrayList<Long> getSidsIDSToServers(){
        return sidsIDSToServers;
    }
    /**
     * Metodo removeRegistroReglasFirewall.
     * Remueve registros que representan reglas del firewall.
     * @param devId DeviceId. Id del OVS donde se encuentra la regla.
     * @param selector TrafficSelector. Selector de trafico de la regla a
     * eliminar.
     */
    public synchronized void removeRegistroRegla(DeviceId devId, TrafficSelector selector){
        RegistroRegla registroRegla;

        registroRegla = new RegistroRegla (selector, devId);
        this.getRulesList().remove(registroRegla);
    }

    /**
     * Metodo findSwitchConnectedToHost. Busca los switches conectados a un host.
     * @param ipAddr String   Direccion ip del host
     * @return Set<DeviceId> Set con los ID de todos los switches conectado al
     * host.
     */
    public Set<DeviceId> findSwitchConnectedToHost(String ipAddr){
        IpAddress     ip;
        Set<Host>     hostSet;
        Set<DeviceId> deviceIds;

        ip = IpAddress.valueOf(ipAddr); // Conversion de IP

        // Obtengo Set con los host que tienen la Ip
        hostSet   = this.hostService.getHostsByIp(ip);
        deviceIds = new HashSet<>();

        // Cada Host tiene un conjunto Hostlocation, desde el cual se puede
        // obtener el Id y el puerto del switch al que esta conectado.
        hostSet.forEach(host -> host.locations().forEach(hl -> deviceIds.add(hl.deviceId())));

        // si no se encontro un dispositivo diretamente conectado se devuelve
        // el conjunto maracado como EDGE, los sw de borde
        return deviceIds;
    }

    /**
     * Busca todos los dispositovos que possen intents que tienen duplicacion de
     * trafico y cuyo destino es el IDS, en cuestion
     * @param ipAddrIDS, ip del IDS
     * @return Set<DeviceId> con trafico duplicado con destino al IDS
     */
    public Set<DeviceId> findSrcSwitchSet(IpAddress ipAddrIDS){

        Set<DeviceId>              objecDevicesSet;
        Set<FilteredConnectPoint>  egressCPSet;
        Iterable<Intent>           intentSet;

        // get Conect Pints IDS ////////////////
        //IpAddress     ip;
        Set<Host>     hostSet;
        Set<HostLocation> hostLocationSet;
        Set<ConnectPoint> cPDevtoIds;

        //ip = IpAddress.valueOf(ipAddrIDS); // Conversion de IP
        // Obtengo Set con los host que tienen la Ip
        hostSet = this.hostService.getHostsByIp(ipAddrIDS);
        if(hostSet.isEmpty())
            return getEdgeSw();

        hostLocationSet = new HashSet<>();
        // Cada Host tiene un conjunto Hostlocation, desde el cual se puede
        // obtener el Id y el puerto del switch al que esta conectado.
        hostSet.forEach(host -> hostLocationSet.addAll(host.locations()));

        // Get IDS Host Connect Points
        cPDevtoIds = new HashSet<>();
        hostLocationSet.forEach(hl-> cPDevtoIds.add(new ConnectPoint(hl.deviceId(), hl.port())));
        // Obtengo Set con los host que tienen la Ip
        // deviceConnectedIDS = findSwitchConnectedToHost(ipAddrIDS);

        objecDevicesSet = new HashSet<>();

        intentSet = this.intentService.getIntents();
        for (Intent intent : intentSet) {
            if (intent.getClass().equals(SinglePointToMultiPointIntent.class)) {
                // cast
                egressCPSet = ((SinglePointToMultiPointIntent) intent).filteredEgressPoints();

                egressCPSet.forEach(filEgressCp -> {
                    if(cPDevtoIds.contains(filEgressCp.connectPoint()))
                        objecDevicesSet.add(filEgressCp.connectPoint().deviceId());

                });// for (FilteredConnectPoint...
            } // intent.getClass().equals...
        } // for (Intent intent : intentSet)...
        return (!objecDevicesSet.isEmpty())? objecDevicesSet : getEdgeSw();
    }

    /**
     * Metodo para encontrar los Devices SW de frontera El metodo devuelve todos
     * los sw's de frontera.
     * @return Set DeviceId con lo sw forntera
     */
    private Set<DeviceId> getEdgeSw(){
        Set<DeviceId>    deviceIds;
        Iterable<Device> devices;

        deviceIds = new HashSet<>();
        // Get all Switches aviables
        devices   = deviceService.getAvailableDevices(Device.Type.SWITCH);

        for (Device dev : devices){
            // busqueda de las anotaciones si no existe rerona "null"
            try{
                if(dev.annotations().value(ANNT).equals(EDGE)){
                    deviceIds.add(dev.id());
                }
            }
            catch (NullPointerException e){
                log.error("No se encuentran las anotaciones EDGE");
            }
        }
        return (!deviceIds.isEmpty())? deviceIds : getAllSwitch();
    }


    /**
     * Metodo getAllSwitch. Permite encontrar los DevicesID de todos los
     * switches de la red.
     * @return Set<DeviceId> Conjunto con todos los deviceId de los switches
     * presentes en la red.
     */
    public Set<DeviceId> getAllSwitch(){
        Set<DeviceId>     deviceIds;
        Iterable <Device> devices;
        deviceIds = new HashSet<>();
        // get switches disponibles
        devices   = deviceService.getAvailableDevices(Device.Type.SWITCH);
        devices.forEach(dev-> deviceIds.add(dev.id()));
        //for (Device dev : devices){deviceIds.add(dev.id());}
        return deviceIds;
    }

    /**
     * Metodo getSIDSmurfAttack. Permite obtener el SID de la alerta de Smurf
     * attack que genera el IDS.
     * @return Long SID de la alerta de Smurf Attack.
     **/

    public Long getSIDSmurfAttack(){
        return this.sidsIDSToServers.get(0);
    }

    /**
     * Metodo getSIDUDPFloodAttack. Permite obtener el SID de la alerta de UDP
     * Flood attack que genera el IDS.
     * @return Long SID de la alerta de UDP Flood.
     **/

    public Long getSIDUDPFloodAttack(){
        return this.sidsIDSToServers.get(7);
    }

    /**
     * Metodo getSIDTCPFloodsAndSlowlorisAttack. Permite obtener los SID propios
     * de las alertas de ataques TCP flood que genera el IDS.
     * @return ArrayList<Long> ArrayList con todos los SID propios de las
     * alertas de ataques TCP flood.
     **/

    public ArrayList<Long> getSIDTCPFloodsAndSlowlorisAttack (){

        ArrayList<Long> lista;

        lista = new ArrayList<>();
        for (int i = 1; i < this.sidsIDSToServers.size(); i++){
            if (i < 7){
                lista.add(sidsIDSToServers.get(i));
            }
        }
        return lista;
    }


    /**
     *  Metodo isAttack. Decide si la alerta recibida forma o no parte de un
     *  ataque y lo clasifica.
     * @param sidAlert Long SID de la alerta recibida del IDS.
     * @param IPSource String IP origen del host que esta potencialmente
     * generando el ataque.
     * @return Enum AttackType Codigo que permite indicar la naturaleza del
     *              ataque: SMURF : Ataque por Smurf Attack a los servidores.
     *              FLOOD : Ataque de otro tipo a los servidores. NO_RECOGNISED
     *              : Falsa alarma.
     */
    public AttackType isAttack(long sidAlert, String IPSource) {
        if (sidAlert == getSIDSmurfAttack()){
            return AttackType.SMURF; // Ataque Smurf Attack to Servers.
        }
        else if (this.sidsIDSToServers.contains(sidAlert)){
            return AttackType.FLOOD; // Otro tipo de ataque a los servidores.
        }
        else {
            return AttackType.NO_RECOGNISED; // Alarma NO RECONOCIDA.
        }
    }

    /**
     * Metodo synchronized y privado writeRule. Escribe las reglas de drop en
     * los OVS especificados con el selector de trafico especificado. Mantiene
     * la lista de reglas insertadas en los OVS.
     * @param devId Set<DeviceId> Conjunto de OVS sobre los cuales se escribirán
     * las reglas.
     * @param selector TrafficSelector Selector de trafico que formara parte de
     * la regla de drop a escribir.
     * @return boolean True si la regla de drop se escribio en por lo menos un
     * device. False en caso contrario.
     */
    private synchronized boolean writeRule (Set<DeviceId> devId, TrafficSelector selector,
                                            String decription){

        boolean          write;
        TrafficTreatment drop;
        RegistroRegla    registroRegla;

        // Tratamiento que proporciona la regla.
        drop  = DefaultTrafficTreatment.builder().drop().build();
        write = false;

        // For each para recorrer devices.
        for (DeviceId deviceId : devId){
            if (!this.getRulesList().contains(new RegistroRegla (selector, deviceId))) {

                registroRegla = new RegistroRegla (selector, deviceId);
                this.getRulesList().add (registroRegla); // Almaceno en lista.
                // Creacion de rule.
                flowObjectiveService.forward(deviceId, DefaultForwardingObjective.builder()
                        .fromApp       (appId)
                        .withSelector  (selector)
                        .withTreatment (drop)
                        .withFlag      (ForwardingObjective.Flag.VERSATILE)
                        .withPriority  (DROP_PRIORITY)
                        .makeTemporary (TIMEOUT_SEC)
                        .add());

                raiseAlarm(deviceId, selector, drop, decription);
                write = true;
            }
        }
        return write;
    }

    /**
     * Raise Alarm
     * @param deviceId, DeviceId
     * @param tSelector, TrafficSelector
     * @param tTreatment, TrafficTreatment
     * @param description, String
     */
    private void raiseAlarm(DeviceId deviceId, TrafficSelector tSelector,
                            TrafficTreatment tTreatment, String description){
        long         timestamp;
        String       uniqueIdentifier;
        AlarmId alarmId;
        DefaultAlarm defaultAlarm;
        Set<Alarm>   alarms;

        uniqueIdentifier = ""+tSelector.hashCode()+tTreatment.hashCode();
        alarmId          = AlarmId.alarmId(deviceId, uniqueIdentifier);
        timestamp        = System.currentTimeMillis();

        defaultAlarm     = new DefaultAlarm.Builder(
                alarmId, deviceId, description, Alarm.SeverityLevel.WARNING, timestamp).build();
        alarms           = new HashSet<>();
        alarms.add(defaultAlarm);
        //alarms.add(defaultAlarm);ç
        try {
            alarmProviderService.updateAlarmList(deviceId, alarms);
        }
        catch (Exception e){
            e.printStackTrace();
            log.error("falle al querer usarlo");
        }
    }

    /**
     * Metodo defAttack. Llama al método writeRule. Genera un selector de
     * trafico de IPV4 que contenga la IP de origen especificada como parametro.
     * Permite activar la defensa en caso de un ataque que no sea del tipo
     * smurf.
     * @param devId Set<DeviceId> Conjunto de OVS sobre los cuales se escribirán
     * las reglas.
     * @param alertpkt Alertpkt Alerta que contiene IP origen a bloquear.
     * @return boolean True si la regla se escribio en por lo menos un device.
     * False en caso contrario.
     */
    public boolean defAttack(Set<DeviceId> devId, Alertpkt alertpkt, String alamrDescription){

        long            signatureId;
        IpPrefix        IPprefixSrc, IPprefixDst;
        TrafficSelector selector;
        TpPort          tpPort;

        IPprefixSrc = IpPrefix.valueOf (alertpkt.getPackageBin().getSourceIP() + "/32");
        IPprefixDst = IpPrefix.valueOf (alertpkt.getPackageBin().getDstIP() + "/32");
        signatureId = alertpkt.getEvent().getSigId();

        if(this.getSIDTCPFloodsAndSlowlorisAttack().contains(signatureId)){
            tpPort   = TpPort.tpPort(alertpkt.getPackageBin().getTcp().getDestinationPort());
            selector = DefaultTrafficSelector.builder()
                    .matchEthType    (Ethernet.TYPE_IPV4)
                    .matchIPSrc      (IPprefixSrc)
                    .matchIPDst      (IPprefixDst)
                    .matchIPProtocol (IPv4.PROTOCOL_TCP)
                    .matchTcpDst     (tpPort)
                    .build();
        }
        else if (signatureId == this.getSIDUDPFloodAttack()){
            tpPort   = TpPort.tpPort(alertpkt.getPackageBin().getUdp().getDestinationPort());
            selector = DefaultTrafficSelector.builder()
                    .matchEthType    (Ethernet.TYPE_IPV4)
                    .matchIPSrc      (IPprefixSrc)
                    .matchIPDst      (IPprefixDst)
                    .matchIPProtocol (IPv4.PROTOCOL_UDP)
                    .matchUdpDst     (tpPort)
                    .build();
        }
        else {
            selector = DefaultTrafficSelector.builder()
                    .matchEthType (Ethernet.TYPE_IPV4)
                    .matchIPSrc   (IPprefixSrc)
                    .matchIPDst   (IPprefixDst)
                    .build();
        }

        // Selector de trafico.
        // Escritura de regla de drop.
        return writeRule(devId, selector, alamrDescription);
    }

    /**
     * Metodo defSmurfAttack. Llama al método writeRule. Genera un selector de
     * trafico de ICMP tipo 8 que contenga la IP de origen y destino
     * especificada en los parámetros. Permite activar la defensa en caso de un
     * ataque de tipo smurf.
     * @param devId Set<DeviceId> Conjunto de OVS sobre los cuales se escribirán
     * las reglas.
     * @param IPdst String IP destino de broadcast.
     * @param IPsrc String IP origen a bloquear.
     * @return boolean True si la regla se escribio en por lo menos un device.
     * False en caso contrario.
     */
    public boolean defSmurfAttack(Set<DeviceId> devId, String IPsrc, String IPdst,
                                  String description){

        IpPrefix        IPprefixSrc, IPprefixDst;
        TrafficSelector selector;

        IPprefixSrc = IpPrefix.valueOf (IPsrc + "/32");
        IPprefixDst = IpPrefix.valueOf (IPdst + "/32");

        // Selector de trafico.
        selector = DefaultTrafficSelector.builder()
                .matchEthType    (Ethernet.TYPE_IPV4)
                .matchIPProtocol (IPv4.PROTOCOL_ICMP)
                .matchIcmpType   (ICMP.TYPE_ECHO_REQUEST)
                .matchIPSrc      (IPprefixSrc)
                .matchIPDst      (IPprefixDst)
                .build();

        // Escritura de regla de drop.
        return writeRule(devId, selector, description);
    }


    /**
     * Clase RegistroRegla. Registro de la regla de firewall colocada en un OVS.
     * Contiene un campo con la direccion IP origen del paquete que genero la
     * alerta y otro campo con el device ID del OVS donde se introdujo la regla.
     */
    private class RegistroRegla {
        private final TrafficSelector selector;
        private final DeviceId        devId;


        RegistroRegla(TrafficSelector selector, DeviceId devId) {
            this.selector = selector;
            this.devId    = devId;
        }

       /* public DeviceId getDevID() {
            return devId;
        }*/


        /*public TrafficSelector getSelector() {
            return this.selector;
        }*/

        @Override
        public int hashCode() {
            return Objects.hash (this.selector, this.devId);
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null || getClass() != obj.getClass()) {
                return false;
            }
            final RegistroRegla other = (RegistroRegla) obj;
            return Objects.equals(this.selector, other.selector);
        }
    }

}
