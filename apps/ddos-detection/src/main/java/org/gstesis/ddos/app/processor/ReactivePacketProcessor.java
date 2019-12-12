package org.gstesis.ddos.app.processor;

import com.google.common.collect.Sets;
import org.onlab.packet.*;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.*;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.host.HostService;
import org.onosproject.net.intent.*;
import org.onosproject.net.packet.*;
import org.onosproject.net.topology.TopologyService;
import org.slf4j.Logger;

import java.util.*;
import java.util.concurrent.*;

import static org.onosproject.net.intent.IntentState.WITHDRAWN;
import static org.slf4j.LoggerFactory.getLogger;

/**
 * Packet processor responsible for forwarding packets along their paths.
 * implements PacketProcessor, Abstraction of an inbound packet processor.
 *
 * @see org.onosproject.net.packet.PacketProcessor
 */
public class ReactivePacketProcessor implements PacketProcessor {
    private static final int DROP_PRIORITY = 40004;
    private static final int TIMEOUT_SEC   = 30; // rule duration (seg).

    private int             intentNormalPri;
    private int             intentDDoslPri;

    private ApplicationId   appId;

    private HostService     hostService;
    private IntentService   intentService;
    private TopologyService topologyService;
    private PacketService   packetService;
    private FlowObjectiveService flowObjectiveService;

    private Set<Key>        intentKeys;
    private Set<Intent>     intentsInstalled;
    private Semaphore       semaphore;

    private final Logger log = getLogger(getClass());


     // Should be a parameter configurable via network configuration or cli
     // The controller must find the closest IDS in order to define where the
     // which one will analyze the traffic
    private IdsResources idsResources;

    // representacion de los estados de un intent. retirado, siendo retirado y
    // solicitud de retirado.
    private static final EnumSet<IntentState> WITHDRAWN_STATES = EnumSet.of(
            WITHDRAWN,
            IntentState.WITHDRAWING,
            IntentState.WITHDRAW_REQ);

    /**
     * Reactive packet Proces do forwarding packets
     * @param appId AppId Onos
     * @param hostService ONOS service
     * @param topologyService ONOS service
     * @param packetService ONOS service
     * @param intentService ONOS service
     * @param intentNormalPri ONOS service
     * @param intentDDoslPri Priority onos service.
     *
     * @see org.onosproject.net.intent.IntentService
     * @see org.onosproject.net.host.HostService
     * @see org.onosproject.net.packet.PacketService
     * @see org.onosproject.net.topology.TopologyService
     */
    public ReactivePacketProcessor(ApplicationId appId, HostService hostService,
                                   TopologyService topologyService, PacketService packetService,
                                   IntentService intentService,
                                   FlowObjectiveService flowObjectiveService,
                                   int intentNormalPri, int intentDDoslPri){

        this.appId            = appId;
        this.hostService      = hostService;
        this.topologyService  = topologyService;
        this.packetService    = packetService;
        this.intentService    = intentService;
        this.intentNormalPri  = intentNormalPri;
        this.intentDDoslPri   = intentDDoslPri;
        // conjunto para uso en ambiente-multihilos
        this.intentKeys       = Sets.newConcurrentHashSet();
        this.intentsInstalled = Sets.newConcurrentHashSet();
        this.semaphore        = new Semaphore(1,true);
        this.idsResources     = IdsResources.getInstance();  // Singleton
        this.flowObjectiveService = flowObjectiveService;

    }

    /**
     * do forwarding
     * @param context PacketContext intput
     */
    @Override
    public void process(PacketContext context) {

        boolean              idsBool;
        ConnectPoint         srcCp;
        Ethernet             ethPkt;
        HostId               srcId, dstId;
        Set<IpAddress>       idsSet;

        TrafficSelector      srcSelector, destSelector;
        FilteredConnectPoint srcFCp, dstFCp;

        idsBool = false;
        // Stop processing if the packet has been handled, since we can't do any
        // more to it.
        if (context.isHandled()) {
            return;
        }
        //InboundPacket pkt = context.inPacket();
        ethPkt = context.inPacket().parsed(); //obtener el obtejeto eth.
        if (ethPkt == null) {
            return;
        }

        srcCp = context.inPacket().receivedFrom();

        srcId = HostId.hostId(ethPkt.getSourceMAC());
        dstId = HostId.hostId(ethPkt.getDestinationMAC());

        // Do we know who this is for? If not, flood and bail. caso broadcast
        Host dst = hostService.getHost(dstId);
        if (dst == null) {
            flood(context);
            return;
        }

        Host src = hostService.getHost(srcId);
        if (src == null) {
            flood(context);
            return;
        }

        if(ethPkt.getEtherType() == Ethernet.TYPE_IPV4){
            IPv4 iPv4 = (IPv4) ethPkt.getPayload();
            if(!src.ipAddresses().contains(Ip4Address.valueOf(iPv4.getSourceAddress())))
                dropSpoff(iPv4, srcCp.deviceId());
        }

        // In order to create connect point we must define a selector that
        // packets match to access to the intent, we cant just connect two
        // ports, because this will forward absolutely all the traffic and the
        // network will crash
        srcSelector  = DefaultTrafficSelector.builder()
                        .matchEthType(Ethernet.TYPE_IPV4)
                        .matchIPSrc(src.ipAddresses().iterator().next().toIpPrefix())
                        .matchIPDst(dst.ipAddresses().iterator().next().toIpPrefix())
                        .build();
        srcFCp       = new FilteredConnectPoint(srcCp, srcSelector);
        destSelector = DefaultTrafficSelector.emptySelector();
        dstFCp       = new FilteredConnectPoint(
                            this.hostService.getHost(dstId).location(),
                            destSelector);

        // Do not create intents when IDS is the origin or destination if
        // (!dst.ipAddresses().containsAll(idsSet) &&
        // !src.ipAddresses().containsAll(idsSet)) {
        idsSet = this.idsResources.getIpAddressSet();
        for (IpAddress idsIp : idsSet) {
            if (dst.ipAddresses().contains(idsIp) || src.ipAddresses().contains(idsIp)) {
                idsBool = true;
                break;
            }
        }
        if (!idsBool)
            setUpConnectivity(srcFCp, dstFCp,null, false);

        // si lo hace el ids tambien se entrgan los paquetes.
        forwardPacketToDst(context, dst);
    }

    void dropSpoff(IPv4 iPv4, DeviceId deviceId){

        IpPrefix         ipPrefix;
        TrafficSelector  srcSelector;
        TrafficTreatment drop;

        ipPrefix = IpPrefix.valueOf(IPv4.fromIPv4Address(iPv4.getSourceAddress())+ "/32");

        srcSelector  = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPSrc(ipPrefix)
                .build();

        drop  = DefaultTrafficTreatment.builder().drop().build();

        this.flowObjectiveService.forward(deviceId, DefaultForwardingObjective.builder()
                .fromApp       (appId)
                .withSelector  (srcSelector)
                .withTreatment (drop)
                .withFlag      (ForwardingObjective.Flag.VERSATILE)
                .withPriority  (DROP_PRIORITY)
                .makeTemporary (TIMEOUT_SEC)
                .add());

        // log.warn(":::Spoof case Ip={}::", ipPrefix.toString());
    }

    /**
     * Install a rule forwarding the packet to the specified port. connex 1:N
     * @param srcCp source connect point
     * @param dstCp dest connect point
     */
    public Key setUpConnectivity(FilteredConnectPoint srcCp, FilteredConnectPoint dstCp,
                                 Host idsHost, boolean duplicateTraffic) {

        int                       priority;
        Key                       key;
        Host                      ids;
        String                    idsKeyString;

        TrafficSelector           idsSelector;
        TrafficSelector           selector;
        TrafficTreatment          treatment;

        Set<FilteredConnectPoint> egressPoints;
        FilteredConnectPoint      filterIdsCp;

        idsKeyString   = "";
        egressPoints = new HashSet<>();
        priority     = intentNormalPri;
        selector     = DefaultTrafficSelector.emptySelector();
        treatment    = DefaultTrafficTreatment.emptyTreatment();

        // Do Acction in Mutex enviroment
        try {
            semaphore.acquire();
        }
        catch (InterruptedException e) {
            log.error("Semaforo Dont Acacquire");
            return null;
        }

        egressPoints.add(dstCp);  // Add initial dst

        // If DoS/DDoS case, Add IDS dst.
        if(duplicateTraffic){

            idsSelector  = DefaultTrafficSelector.builder()
                                .matchEthType(Ethernet.TYPE_IPV4)
                                .build();
            // ids         = findIds(dstCp);
            // Find The nearest IDS to srcCp
            // ids          = findIds(srcCp);
            filterIdsCp  = new FilteredConnectPoint(idsHost.location(), idsSelector);
            // Add The nearest IDS
            egressPoints.add(filterIdsCp);

            priority     = intentDDoslPri;
            idsKeyString = filterIdsCp.toString();
        }

        key = (srcCp.toString().compareTo(dstCp.toString()) < 0)?
                Key.of(srcCp.toString() + dstCp.toString() + idsKeyString, appId): // True
                Key.of(dstCp.toString() + srcCp.toString() + idsKeyString, appId); // False

        intentKeys.add(key);

        if (intentService.getIntent(key) != null){
            if (WITHDRAWN_STATES.contains(intentService.getIntentState(key))) {
                buildIntent(key, srcCp, egressPoints, priority, selector, treatment);
            }
        }
        else {
            buildIntent(key, srcCp, egressPoints, priority, selector, treatment);
        }
        semaphore.release();

        return key; //retorna la clave del ultimo intent creado.
    }

    /**
     * build intent
     * @param key, intent key
     * @param srcCp, connect point src
     * @param egressPoints, Counjunto de destinos (destinoHost, IDS)
     * @param priority, prioridad del intent
     * @param selector, traffic selector
     * @param treatment, traffic treatment
     */
    private void buildIntent(Key key, FilteredConnectPoint srcCp,
                             Set<FilteredConnectPoint> egressPoints,
                             int priority, TrafficSelector selector, TrafficTreatment treatment){

        SinglePointToMultiPointIntent multipointIntent;

        multipointIntent = SinglePointToMultiPointIntent.builder()
                            .appId                (appId)
                            .key                  (key)
                            .filteredIngressPoint (srcCp)
                            .filteredEgressPoints (egressPoints)
                            .priority             (priority)
                            .selector             (selector)
                            .treatment            (treatment)
                            .build();

        intentService.submit(multipointIntent);
        intentsInstalled.add(multipointIntent);
    }

    /**
     * Floods the specified packet if permissible.
     * si es boradcast se reenvia, caso contrario se bloquea.
     * @param context context
     */
    private void flood(PacketContext context) {
        if (this.topologyService.isBroadcastPoint(
                this.topologyService.currentTopology(), context.inPacket().receivedFrom()))
            packetOut(context, PortNumber.FLOOD);
        else
            context.block();
    }

    /**
     * Sends a packet out the specified port.
     * @param context conetext packet
     * @param portNumber, NumberPort
     */
    private void packetOut(PacketContext context, PortNumber portNumber) {
        context.treatmentBuilder().setOutput(portNumber);
        context.send();
    }

    /**
     * Realiza el reenvio de paquetes
     * @param context contexto del paquete
     * @param dst host del destino
     */
    private void forwardPacketToDst(PacketContext context, Host dst) {
        TrafficTreatment treatment;
        OutboundPacket   packet;

        treatment = DefaultTrafficTreatment.builder().setOutput(dst.location().port()).build();
        packet    = new DefaultOutboundPacket(dst.location().deviceId(),
                                              treatment, context.inPacket().unparsed());
        //Entrega paquete, tarea realizada por el controlador.
        this.packetService.emit(packet);
    }


    /**
     * Delete intents installed by this application
     */
    public void deleteIntents(){
        CompletableFuture<Void> completableFuture;

        completableFuture = new CompletableFuture<>();

        IntentListener listener = e -> { // operador lambda
            // remueve los intents con eventos retirado.
            if (e.type() == IntentEvent.Type.WITHDRAWN) {
                intentKeys.remove(e.subject().key());
            }
            if (intentKeys.isEmpty()) {
                completableFuture.complete(null);
            }
        };
        intentService.addListener(listener);
        intentsInstalled.forEach(intentService::withdraw); //retiro de los intents
        try {
            if (!intentsInstalled.isEmpty()) {
                // Wait 1.5 seconds for each Intent
                completableFuture.get(intentsInstalled.size() * 1500L, TimeUnit.MILLISECONDS);
            }
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            log.info("Encountered exception while withdrawing intents: " + e.toString());
        } finally {
            intentService.removeListener(listener);
        }
        intentsInstalled.forEach(intentService::purge);
    }

    /**
     * metodo busca los devices Id's de los Sw conectados al a los ID's
     * @return Set con deviceIds conectados a los distintos IDS's
     */
    public Map<DeviceId,Host> getDevIds(){

        Set<Host>               hostSet;
        Set<HostLocation>       hostLocationSet;
        HashMap<DeviceId, Host> hashMap;
        Set<IpAddress>          idsSet;

        // Obtencion de Todos las IDS ip configuradas
        idsSet = this.idsResources.getIpAddressSet();
        hashMap = new HashMap<>();

        if(idsSet.isEmpty()) {
            log.error("No existen ip configuradas");
            return hashMap;  // Error Case
        }

        // Cada Host tiene un conjunto Hostlocation, desde el cual se
        // puede obtener el Id y el puerto del switch al que esta conectado.
        for (IpAddress ip: idsSet) {

            hostSet = hostService.getHostsByIp(ip);  // Get IDS host
            for (Host host : hostSet) {

                hostLocationSet = host.locations();  // Get IDS Location
                for (HostLocation hostLocation: hostLocationSet) {
                    // Put map DeviceID Switch, Host IDS.
                    hashMap.put(hostLocation.deviceId(), host);
                }
            }
        }
        return hashMap;
    }
}
